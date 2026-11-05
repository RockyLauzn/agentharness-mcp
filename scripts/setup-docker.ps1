$ErrorActionPreference = 'Stop'
wsl -d Ubuntu-22.04 -u root -- bash -lc 'apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y docker.io && systemctl start docker'
if ($LASTEXITCODE -ne 0) { throw 'Docker installation failed' }
wsl -d Ubuntu-22.04 -u root -- docker build -t agent-harness:mvp /mnt/f/agent_harness
if ($LASTEXITCODE -ne 0) { throw 'Docker image build failed' }
