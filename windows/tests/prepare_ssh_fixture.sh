#!/usr/bin/env bash
# Disposable imported WSL distribution only. Never run on Rocky01.
set -euo pipefail
test "$(id -u)" = 0
case "${WSL_DISTRO_NAME:-}" in RockyGatewayCI*) ;; *) exit 2 ;; esac
fixture_repo=${1:?checkout required}
fixture_public_key=${2:?public key required}
fixture_port=${3:?loopback port required}
[[ "$fixture_port" =~ ^[0-9]+$ ]] && (( fixture_port > 1024 && fixture_port < 65536 ))
test ! -e /opt/rocky-ssh-ci

# Prevent package installation from starting a default network-facing sshd.
printf '#!/bin/sh\nexit 101\n' > /usr/sbin/policy-rc.d
chmod 755 /usr/sbin/policy-rc.d
timeout 180s apt-get -o Acquire::Retries=3 -o Acquire::http::Timeout=30 update -qq
timeout 300s env DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends python3 openssh-server ca-certificates
useradd --create-home --shell /bin/sh --password '*' engci
chmod 700 /home/engci
install -d -m 755 /opt/rocky-ssh-ci/scripts /opt/rocky-ssh-ci/windows/tests /run/sshd
cp "$fixture_repo"/*.py /opt/rocky-ssh-ci/
cp "$fixture_repo/scripts/smoke_evidence.py" /opt/rocky-ssh-ci/scripts/
cp "$fixture_repo/windows/tests/ssh_ci_endpoint.py" /opt/rocky-ssh-ci/windows/tests/
chmod -R go-w /opt/rocky-ssh-ci
install -d -o engci -g engci -m 700 /home/engci/.ssh
{ printf 'restrict '; cat "$fixture_public_key"; } > /home/engci/.ssh/authorized_keys
chown engci:engci /home/engci/.ssh/authorized_keys
chmod 600 /home/engci/.ssh/authorized_keys
install -d -m 700 /run/rocky-ssh-ci
ssh-keygen -q -t ed25519 -N '' -f /run/rocky-ssh-ci/host_ed25519
cat > /run/rocky-ssh-ci/sshd_config <<EOF
AddressFamily inet
ListenAddress 127.0.0.1
Port $fixture_port
HostKey /run/rocky-ssh-ci/host_ed25519
PidFile /run/rocky-ssh-ci/sshd.pid
AuthorizedKeysFile /home/engci/.ssh/authorized_keys
StrictModes yes
AllowUsers engci
PermitRootLogin no
PubkeyAuthentication yes
AuthenticationMethods publickey
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitEmptyPasswords no
UsePAM no
UseDNS no
PermitTTY no
PermitUserEnvironment no
AllowTcpForwarding no
AllowAgentForwarding no
X11Forwarding no
PermitTunnel no
GatewayPorts no
LogLevel VERBOSE
Subsystem sftp /usr/lib/openssh/sftp-server
ForceCommand exec /usr/bin/python3 -u /opt/rocky-ssh-ci/windows/tests/ssh_ci_endpoint.py dispatch
EOF
/usr/sbin/sshd -t -f /run/rocky-ssh-ci/sshd_config
/usr/sbin/sshd -f /run/rocky-ssh-ci/sshd_config -E /run/rocky-ssh-ci/sshd.log
