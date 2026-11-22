param([string]$Image = 'fixlevelup-p0305-browser:local')
$ErrorActionPreference = 'Stop'
$engine = 'npipe:////./pipe/dockerDesktopLinuxEngine'
$pg = 'postgres:18.7-bookworm@sha256:1757c628698dd1ca67ff7a5fc386bfd91040afc62a45484c346c788b0cbe5402'
$id = [guid]::NewGuid().ToString('N').Substring(0,24)
$db = "fixlevelup-p0305-pg-$id"
$browser = "fixlevelup-p0305-live-$id"
function Invoke-ProofDocker {
    & docker --host $engine @args
    if ($LASTEXITCODE -ne 0) { throw 'Isolated Docker command failed' }
}
$owned = $false
try {
    $password = [Convert]::ToHexString([Security.Cryptography.RandomNumberGenerator]::GetBytes(32)).ToLowerInvariant()
    $env:POSTGRES_PASSWORD = $password
    $env:P0305_PG_BOOTSTRAP = $password
    Invoke-ProofDocker image inspect --format '{{.Id}}' $Image | Out-Null
    Invoke-ProofDocker run -d --pull never --network none --name $db --mount "type=volume,source=$db-data,target=/var/lib/postgresql" `
        -e POSTGRES_PASSWORD -e POSTGRES_DB=fixlevelup_dev -e POSTGRES_USER=p0305_postgres `
        -e POSTGRES_INITDB_ARGS=--auth-host=scram-sha-256 $pg `
        -c 'listen_addresses=127.0.0.1' -c 'port=55432' -c "cluster_name=p0305-$id" | Out-Null
    $owned = $true
    Invoke-ProofDocker create --pull never --network "container:$db" --name $browser --shm-size 1g --memory 4g --cpus 2 `
        -e P0305_PG_BOOTSTRAP -e P0305_ISOLATED_BROWSER=1 -e "P0305_NAMESPACE=$id" $Image node infra/p0305-browser-smoke/live.mjs | Out-Null
    # The fixture launcher can be corrected independently from immutable production artifacts.
    foreach ($fixture in @('live.mjs', 'database.mjs')) {
        Invoke-ProofDocker cp (Join-Path $PSScriptRoot $fixture) "${browser}:/p0305/infra/p0305-browser-smoke/$fixture"
    }
    $root = Join-Path $PSScriptRoot '../..'
    Invoke-ProofDocker cp (Join-Path $root 'packages/browser-tooling/tests/p0305-live.spec.ts') "${browser}:/p0305/packages/browser-tooling/tests/p0305-live.spec.ts"
    Invoke-ProofDocker cp (Join-Path $root 'packages/browser-tooling/fixtures/p0305/live-reporter.mjs') "${browser}:/p0305/packages/browser-tooling/fixtures/p0305/live-reporter.mjs"
    Invoke-ProofDocker start -a $browser
} finally {
    $env:POSTGRES_PASSWORD = $null
    $env:P0305_PG_BOOTSTRAP = $null
    $password = $null
    if ($owned) { Invoke-ProofDocker stop $db | Out-Null }
}
