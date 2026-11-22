param([string]$Image = 'fixlevelup-p0305-browser:local')
$ErrorActionPreference = 'Stop'
$engine = 'npipe:////./pipe/dockerDesktopLinuxEngine'
$base = 'fixlevelup-browser-proof:p0111c'
$expectedBase = 'sha256:f0032e1812d4e047d3050de6821f5387fc9a5e544b1e383b4e12d192432feecb'
$pg = 'postgres:18.7-bookworm@sha256:1757c628698dd1ca67ff7a5fc386bfd91040afc62a45484c346c788b0cbe5402'
function Invoke-ProofDocker {
    & docker --host $engine @args
    if ($LASTEXITCODE -ne 0) { throw 'Isolated Docker command failed' }
}
$actualBase = Invoke-ProofDocker image inspect --format '{{.Id}}' $base
if ($actualBase -ne $expectedBase) { throw 'Matching pinned proof base missing' }
Invoke-ProofDocker image inspect --format '{{.Id}}' $pg | Out-Null
Invoke-ProofDocker build --network default --pull=false -f infra/p0305-browser-smoke/Dockerfile -t $Image .
