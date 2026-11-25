param(
    [string]$Image = 'fixlevelup-p0404-browser:local',
    [switch]$FixtureOnly
)
$ErrorActionPreference = 'Stop'
$engine = 'npipe:////./pipe/dockerDesktopLinuxEngine'
$pg = 'postgres:18.7-bookworm@sha256:1757c628698dd1ca67ff7a5fc386bfd91040afc62a45484c346c788b0cbe5402'
$id = [Convert]::ToHexString([Security.Cryptography.RandomNumberGenerator]::GetBytes(12)).ToLowerInvariant()
$db = "fixlevelup-p0404-pg-$id"
$browser = "fixlevelup-p0404-live-$id"
$database = "fixlevelup_p04_browser_test_$id"
$pgId = $null
$browserId = $null
function Invoke-ProofDocker {
    & docker --host $engine @args
    if ($LASTEXITCODE -ne 0) { throw 'Isolated Docker command failed' }
}
function Assert-IsolatedContainer([string]$ContainerId, [string]$Name, [string]$Network) {
    if ($ContainerId -cnotmatch '^[a-f0-9]{64}$') { throw 'Invalid owned container ID' }
    $identity = Invoke-ProofDocker inspect --format '{{.Id}} {{.Name}} {{index .Config.Labels "fixlevelup.p0404.proof"}} {{.HostConfig.NetworkMode}} {{len .HostConfig.PortBindings}}' $ContainerId
    if ($identity -cne "$ContainerId /$Name $id $Network 0") { throw 'Refusing unverified Docker container ownership or network' }
}
$oldPostgres = $env:POSTGRES_PASSWORD
$oldFixture = $env:P0404_PG_BOOTSTRAP
try {
    if ((Invoke-ProofDocker info --format '{{.OSType}}') -cne 'linux') { throw 'Docker Linux engine required' }
    $imageId = Invoke-ProofDocker image inspect --format '{{if eq .Os "linux"}}{{.Id}}{{end}}' $Image
    if ($imageId -cnotmatch '^sha256:[a-f0-9]{64}$') { throw 'Linux proof image required' }
    Invoke-ProofDocker image inspect --format '{{.Id}}' $pg | Out-Null
    $password = [Convert]::ToHexString([Security.Cryptography.RandomNumberGenerator]::GetBytes(32)).ToLowerInvariant()
    $env:POSTGRES_PASSWORD = $password
    $env:P0404_PG_BOOTSTRAP = $password
    # Override the image VOLUME with fresh in-memory storage; no working DB,
    # bind mount or named/anonymous persistent database volume is used.
    $pgId = Invoke-ProofDocker create --pull never --network none --name $db --label "fixlevelup.p0404.proof=$id" `
        --tmpfs '/var/lib/postgresql:rw,nosuid,nodev,noexec,size=512m' `
        -e POSTGRES_PASSWORD -e "POSTGRES_DB=$database" -e POSTGRES_USER=p0404_postgres `
        -e POSTGRES_INITDB_ARGS=--auth-host=scram-sha-256 $pg `
        -c 'listen_addresses=127.0.0.1' -c 'port=55432' -c "cluster_name=p0404-$id"
    Assert-IsolatedContainer $pgId $db 'none'
    $storage = Invoke-ProofDocker inspect --format '{{len .Mounts}} {{index .HostConfig.Tmpfs "/var/lib/postgresql"}}' $pgId
    if ($storage -cne '0 rw,nosuid,nodev,noexec,size=512m') { throw 'Refusing persistent PostgreSQL backing storage' }
    Write-Output "P04-04 owned PostgreSQL container: $db $pgId"
    Invoke-ProofDocker start $pgId | Out-Null
    $fixtureFlag = if ($FixtureOnly) { '1' } else { '0' }
    $browserId = Invoke-ProofDocker create --pull never --network "container:$pgId" --name $browser --label "fixlevelup.p0404.proof=$id" `
        --shm-size 1g --memory 4g --cpus 2 -e P0404_PG_BOOTSTRAP -e P0404_ISOLATED_BROWSER=1 -e "P0404_NAMESPACE=$id" `
        -e "P0404_FIXTURE_ONLY=$fixtureFlag" $imageId node infra/p0404-browser-smoke/live.mjs
    Assert-IsolatedContainer $browserId $browser "container:$pgId"
    Write-Output "P04-04 owned browser container: $browser $browserId"
    Write-Output "P04-04 immutable production proof image: $imageId"
    # Only test tooling is overlaid; Next/Nest, Prisma and all dependencies
    # remain the exact compiled artifacts from the chosen image.
    Invoke-ProofDocker cp $PSScriptRoot "${browserId}:/p0305/infra/"
    # The shared launcher fixture is owned by the P03-05 directory; overlay it
    # so a fixture correction never requires rebuilding the immutable image.
    Invoke-ProofDocker cp (Join-Path $PSScriptRoot '../p0305-browser-smoke/launch.mjs') "${browserId}:/p0305/infra/p0305-browser-smoke/launch.mjs"
    if (!$FixtureOnly) {
        $root = Join-Path $PSScriptRoot '../..'
        Invoke-ProofDocker cp (Join-Path $root 'packages/browser-tooling/playwright.p0404.config.ts') "${browserId}:/p0305/packages/browser-tooling/playwright.p0404.config.ts"
        Invoke-ProofDocker cp (Join-Path $root 'packages/browser-tooling/tests/p0404-live.spec.ts') "${browserId}:/p0305/packages/browser-tooling/tests/p0404-live.spec.ts"
        Invoke-ProofDocker cp (Join-Path $root 'packages/browser-tooling/fixtures/p0404') "${browserId}:/p0305/packages/browser-tooling/fixtures/"
    }
    Invoke-ProofDocker start -a $browserId
    if ((Invoke-ProofDocker inspect --format '{{.State.ExitCode}}' $browserId) -cne '0') { throw 'Proof fixture failed' }
} finally {
    $env:POSTGRES_PASSWORD = $oldPostgres
    $env:P0404_PG_BOOTSTRAP = $oldFixture
    $password = $null
    if ($browserId) {
        Assert-IsolatedContainer $browserId $browser "container:$pgId"
        Invoke-ProofDocker stop $browserId | Out-Null
        Invoke-ProofDocker rm $browserId | Out-Null
    }
    if ($pgId) {
        Assert-IsolatedContainer $pgId $db 'none'
        Invoke-ProofDocker stop $pgId | Out-Null
        Invoke-ProofDocker rm $pgId | Out-Null
    }
}
