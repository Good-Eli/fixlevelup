param(
    [string]$Image = 'fixlevelup-p0305-browser:local',
    # Default: the accepted pinned base. A different base may only be used when
    # BOTH parameters are given explicitly; it is then verified and recorded,
    # never silently retagged.
    [string]$BaseImage = 'fixlevelup-browser-proof:p0111c',
    [string]$BaseId = ''
)
$ErrorActionPreference = 'Stop'
$engine = 'npipe:////./pipe/dockerDesktopLinuxEngine'
$pinnedBase = 'fixlevelup-browser-proof:p0111c'
$pinnedBaseId = 'sha256:f0032e1812d4e047d3050de6821f5387fc9a5e544b1e383b4e12d192432feecb'
$pg = 'postgres:18.7-bookworm@sha256:1757c628698dd1ca67ff7a5fc386bfd91040afc62a45484c346c788b0cbe5402'
# Exact browser-proof toolchain contract the P03-05/P04-04 images are built on.
$requiredEnv = @('PATH=/usr/local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin',
    'PLAYWRIGHT_BROWSERS_PATH=/ms-playwright', 'CI=1', 'NEXT_TELEMETRY_DISABLED=1',
    'COREPACK_ENABLE_AUTO_PIN=0', 'COREPACK_DEFAULT_TO_LATEST=0', 'COREPACK_HOME=/opt/fixlevelup-corepack',
    'PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD=1')
function Invoke-ProofDocker {
    & docker --host $engine @args
    if ($LASTEXITCODE -ne 0) { throw 'Isolated Docker command failed' }
}
if ($BaseImage -ceq $pinnedBase) {
    if ($BaseId -and $BaseId -cne $pinnedBaseId) { throw 'Pinned base ID cannot be overridden' }
    $actualBase = Invoke-ProofDocker image inspect --format '{{.Id}}' $pinnedBase
    if ($actualBase -cne $pinnedBaseId) { throw 'Matching pinned proof base missing' }
    Write-Output "P03-05 build base: accepted pinned $pinnedBase $pinnedBaseId"
} else {
    if (-not $BaseId) { throw 'A non-default base requires an explicit -BaseId' }
    if ($BaseId -cnotmatch '^sha256:[a-f0-9]{64}$') { throw 'Invalid explicit base ID' }
    $actualBase = Invoke-ProofDocker image inspect --format '{{.Id}}' $BaseImage
    if ($actualBase -cne $BaseId) { throw 'Explicit base ID does not match the selected image' }
    # Verify the explicit base really is the browser-proof toolchain, not an
    # arbitrary image that happens to carry the right tag.
    $history = Invoke-ProofDocker history --no-trunc --format '{{.CreatedBy}}' $BaseImage
    foreach ($step in @('node infra/linux-proof/source-check.mjs', 'corepack pnpm install --frozen-lockfile --ignore-scripts',
        'corepack pnpm peers check && corepack pnpm run db:generate')) {
        if (-not ($history | Select-String -SimpleMatch $step)) { throw 'Explicit base is not the reviewed browser-proof image' }
    }
    $envJson = Invoke-ProofDocker image inspect --format '{{json .Config.Env}}' $BaseImage
    $envList = $envJson | ConvertFrom-Json
    foreach ($required in $requiredEnv) {
        if ($envList -cnotcontains $required) { throw 'Explicit base toolchain environment mismatch' }
    }
    $probe = Invoke-ProofDocker run --rm --network none --entrypoint sh $BaseImage -c `
        'node --version; test -d /workspace/node_modules/.cache/pnpm-store && echo store-ok; ls /ms-playwright | grep -c "^chromium-"'
    $lines = @($probe | Where-Object { $_ -ne '' })
    if ($lines[0] -cne 'v24.22.3' -or $lines -cnotcontains 'store-ok' -or [int]$lines[-1] -lt 1) {
        throw 'Explicit base toolchain probe failed'
    }
    Write-Output "P03-05 build base: EXPLICITLY DECLARED non-default base $BaseImage $actualBase (toolchain verified: node v24.22.3, pnpm store, Playwright browsers)"
}
Invoke-ProofDocker image inspect --format '{{.Id}}' $pg | Out-Null
# Docker/BuildKit cannot take a bare image ID in FROM (it is parsed as a remote
# repository), so the FROM reference is the tag name. Immutability is therefore
# enforced by evidence instead of by syntax: the tag is pinned to the exact
# approved ID immediately before the build, and the produced image's own layer
# chain must START WITH the approved base's exact layer chain afterwards — a
# moved tag or a different base would break that prefix and fail the build.
$baseLayers = Invoke-ProofDocker image inspect --format '{{json .RootFS.Layers}}' $BaseImage
Invoke-ProofDocker build --network default --pull=false --build-arg "PROOF_BASE=$BaseImage" -f infra/p0305-browser-smoke/Dockerfile -t $Image .
$builtId = Invoke-ProofDocker image inspect --format '{{.Id}}' $Image
$builtLayers = Invoke-ProofDocker image inspect --format '{{json .RootFS.Layers}}' $Image
$base = $baseLayers | ConvertFrom-Json
$built = $builtLayers | ConvertFrom-Json
if ($built.Count -le $base.Count) { throw 'Built image does not extend the declared base' }
for ($i = 0; $i -lt $base.Count; $i++) {
    if ($built[$i] -cne $base[$i]) { throw 'Built image layer chain does not start with the declared base' }
}
Write-Output "P03-05 built image: $Image $builtId"
Write-Output "P03-05 layer proof: base $BaseImage $actualBase has $($base.Count) layers; built image reuses all of them as an exact prefix ($($built.Count) layers total)"
