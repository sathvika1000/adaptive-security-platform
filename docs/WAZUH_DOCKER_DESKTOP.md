# Wazuh and Docker Desktop on an Apple Silicon Mac

Docker Desktop is already installed on the target Mac. This guide connects the
platform to the official Wazuh 4.14.8 single-node stack using Wazuh's JSON
alert file. It is a development setup, not an internet-facing deployment.

Wazuh lists ARM64, at least four CPU cores, 8 GB of RAM available to its Docker
host, and 50 GB of Docker storage for the full single-node stack. Its published
Docker instructions list Linux and Windows; the Apple Silicon Docker Desktop
path here still needs a live check on the target Mac. The full stack includes
the manager, indexer, and dashboard. The application-only Compose stack can
be run first with a smaller Docker allocation.

## 1. Check Docker Desktop

Start Docker Desktop, wait for the engine to be ready, then run in Terminal:

```sh
docker version
docker compose version
docker info --format 'OS={{.OSType}} Arch={{.Architecture}} CPUs={{.NCPU}} RAM-bytes={{.MemTotal}}'
df -h ~
```

Expect `linux` and `aarch64`/`arm64` for the Docker engine architecture.
Compose must be 2.24.4 or newer for the port override below. Before pulling
Wazuh, check Docker Desktop **Settings > Resources** for at least four CPUs,
at least 8 GB of memory, and at least 50 GB of disk capacity with free host
space. On a 16 GB Mac, this allocation can crowd other applications. Stop
the stack when finished. The indexer also requires the Linux VM's
`vm.max_map_count` to be at least 262144; check with
`docker run --rm alpine sysctl vm.max_map_count` if it fails to start. Do not
set the macOS host's sysctl for a Linux VM issue.

## 2. Start the platform alone

Clone this repository on the Mac if needed. From its root:

```sh
export ASP_API_KEY="$(openssl rand -hex 32)"
docker compose up --build -d
docker compose ps
python3 scripts/replay_demo.py
```

Keep this Terminal session or store the key in a local, ignored `.env` file;
the same key must be supplied when starting the forwarder. `python3` is only
used for the replay script; the container provides Python 3.12 for the app.
The API is at `http://127.0.0.1:8000` and `/ready` should return 200.

## 3. Start Wazuh's official single-node stack

From the parent directory of the platform repository:

```sh
git clone --branch v4.14.8 --depth 1 https://github.com/wazuh/wazuh-docker.git
cd wazuh-docker/single-node
docker compose -p asp-wazuh -f generate-indexer-certs.yml run --rm generator
docker compose -p asp-wazuh -f docker-compose.yml \
  -f ../../adaptive-security-platform/deploy/wazuh-loopback.yaml config --quiet
docker compose -p asp-wazuh -f docker-compose.yml \
  -f ../../adaptive-security-platform/deploy/wazuh-loopback.yaml up -d
docker compose -p asp-wazuh -f docker-compose.yml \
  -f ../../adaptive-security-platform/deploy/wazuh-loopback.yaml ps
```

These relative paths assume the two repositories are siblings. The overlay
replaces Wazuh's host port list so the manager and dashboard bind to loopback,
and the indexer has no published host port. Inspect the resolved `config`
before `up` if you change either file. Open `https://localhost:8443` for the
dashboard. The official stack's initial dashboard credentials are `admin` /
`SecretPassword`; change them before any broader access. The self-signed
certificate causes a browser warning. Indexer startup can take a minute or
more.

## Certificate permission repair on macOS

If the generator reports `cp: cannot create regular file
'/certificates/root-ca-manager.pem': Permission denied` and manager startup
cannot mount that path, the two manager CA copies were not written. Wazuh's
generator changes the certificate directory to read-only before that copy.
From `~/wazuh-docker/single-node`, repair only those missing copies:

```sh
(
  set -e
  certs=config/wazuh_indexer_ssl_certs
  test -f "$certs/root-ca.pem"
  test -f "$certs/root-ca.key"
  chmod u+w "$certs"
  cp "$certs/root-ca.pem" "$certs/root-ca-manager.pem"
  cp "$certs/root-ca.key" "$certs/root-ca-manager.key"
  chmod 400 "$certs/root-ca-manager.pem" "$certs/root-ca-manager.key"
  chmod u-w "$certs"
)
```

Then repeat the `docker compose ... up -d` and `ps` commands above. Do not
rerun the generator against a partially started stack, as that would replace
its CA and certificates. If any repair command fails, inspect
`ls -ld config/wazuh_indexer_ssl_certs` and
`ls -l config/wazuh_indexer_ssl_certs/root-ca*` before changing permissions
further. Never paste the contents of a private `.key` file.

## 4. Connect the alert file

Back in the platform repository, in the same Terminal session with
`ASP_API_KEY` set:

```sh
docker volume inspect asp-wazuh_wazuh_logs
docker compose -f compose.yaml -f compose.wazuh.yaml config --quiet
docker compose -f compose.yaml -f compose.wazuh.yaml up --build -d
docker compose -f compose.yaml -f compose.wazuh.yaml ps
docker compose -f compose.yaml -f compose.wazuh.yaml logs --tail=50 forwarder
```

The sidecar reads the official manager's named log volume read-only and writes
its own persistent cursor. It runs as root because the Wazuh alert file may
have restricted permissions; the platform API itself remains unprivileged.
The shared network namespace lets the sidecar contact the API on loopback.
If Wazuh has not produced `alerts.json` yet, the forwarder retries on its
restart policy. A malformed alert or failed API delivery stops on that line;
check its logs rather than deleting the cursor.
The forwarder logs `{"event":"wazuh_alerts_forwarded","count":N}` after a
successful batch. An empty log when no alerts arrive is normal. Its Compose
service intentionally has no inherited API health check: `Up` says that the
forwarder process is running; `/ready` checks the platform API separately.
Confirm delivery by retrieving a Wazuh event from the API as shown below.

## 5. Verify Wazuh decoding and incident correlation

A manager-local SCA alert can verify the forwarding path. Retrieve an alert
ID from `alerts.json`, then use
`curl -fsS -H "X-API-Key: $ASP_API_KEY"
http://127.0.0.1:8000/v1/events/wazuh/<ALERT_ID>` to confirm that the
platform stored it. A new Terminal session must restore the same API key;
you can capture it without displaying it using
`export ASP_API_KEY="$(docker exec adaptive-security-platform-platform-1 printenv ASP_API_KEY)"`.

For a repeatable authentication test, the pinned Wazuh manager configuration
already monitors `/var/ossec/logs/active-responses.log` as syslog. Append two
clearly synthetic SSH lines there. This exercises the Wazuh log collector,
SSH decoder and rule 5710, JSON alert writer, forwarder, and correlation API.
It does not represent actual SSH login attempts. From the platform repository:

```sh
docker compose -p asp-wazuh \
  -f ../wazuh-docker/single-node/docker-compose.yml \
  -f deploy/wazuh-loopback.yaml exec -T -u 0 wazuh.manager sh -ec '
log=/var/ossec/logs/active-responses.log
test -f "$log"
stamp=$(date "+%b %e %H:%M:%S")
printf "%s wazuh.manager sshd[4242]: Invalid user asp-demo from 198.51.100.42 port 55201\n" "$stamp" >> "$log"
printf "%s wazuh.manager sshd[4243]: Invalid user asp-demo from 198.51.100.42 port 55202\n" "$stamp" >> "$log"
'
```

After several seconds, verify two distinct alert IDs with `srcuser`
`asp-demo`, then retrieve the incident:

```sh
docker compose -p asp-wazuh \
  -f ../wazuh-docker/single-node/docker-compose.yml \
  -f deploy/wazuh-loopback.yaml exec -T wazuh.manager \
  sh -c "grep 'asp-demo' /var/ossec/logs/alerts/alerts.json | tail -n 2"
curl -fsS -H "X-API-Key: $ASP_API_KEY" http://127.0.0.1:8000/v1/incidents
```

The expected incident has user `asp-demo`, host `wazuh.manager`, and two
event IDs. Running the test again more than 15 minutes later forms another
incident because the correlation window has elapsed. The test was validated
on Apple Silicon Docker Desktop with Wazuh 4.14.8. For real endpoint
coverage, enroll a Wazuh agent and confirm its authentication alerts have
a user (`dstuser` or `srcuser`) and agent name; manager-local test events do
not monitor the Mac itself.

## 6. Enroll the Mac itself (optional endpoint coverage)

The manager-local SSH test proves the integration but does not monitor macOS.
Wazuh 4.14.8 offers an Apple Silicon agent package. The agent runs persistently
with elevated privileges and sends host security telemetry to this manager.
This local development stack publishes enrollment (1515/TCP) and event
transport (1514/TCP) on 127.0.0.1, so `WAZUH_MANAGER='127.0.0.1'` applies
only to an agent installed on this same Mac. Do not use it for another host.

On the Mac, first check whether an agent already exists:

```sh
test -e /Library/Ossec/etc/ossec.conf && echo 'Existing agent: inspect its configuration' || echo 'No agent installed'
```

If no agent is installed, download and install the pinned ARM64 package:

```sh
cd ~/Downloads
(
  set -e
  curl -fL -O https://packages.wazuh.com/4.x/macos/wazuh-agent-4.14.8-1.arm64.pkg
  pkgutil --check-signature wazuh-agent-4.14.8-1.arm64.pkg
  umask 077
  printf "WAZUH_MANAGER='127.0.0.1'\n" > /tmp/wazuh_envs
  sudo installer -pkg wazuh-agent-4.14.8-1.arm64.pkg -target /
  rm -f /tmp/wazuh_envs
  sudo launchctl bootstrap system /Library/LaunchDaemons/com.wazuh.agent.plist
)
```

Do not rerun the installer over an existing agent without first inspecting
its manager address and enrollment state. The `sudo` commands prompt for the
Mac administrator password locally; do not paste it into a chat or repository.

Check the agent and manager registration:

```sh
sudo /Library/Ossec/bin/wazuh-control status
sudo tail -n 30 /Library/Ossec/logs/ossec.log
cd ~/adaptive-security-platform
docker compose -p asp-wazuh \
  -f ../wazuh-docker/single-node/docker-compose.yml \
  -f deploy/wazuh-loopback.yaml exec -T wazuh.manager \
  /var/ossec/bin/agent_control -l
```

Look for an `Active` agent with the Mac's computer name in the CLI or
**Agents > Summary** in the dashboard. The agent may take a short time to
enroll and report. If it does not, check its local log and that Docker
Desktop is running and ports 1514/1515 remain published. The manager stack
must be running whenever this agent tries to report.
## Stop and restart

```sh
docker compose -f compose.yaml -f compose.wazuh.yaml down
docker compose -p asp-wazuh -f ../wazuh-docker/single-node/docker-compose.yml \
  -f deploy/wazuh-loopback.yaml down
```

These commands preserve the SQLite, alert, and cursor volumes. Do not append
`-v` unless intentionally resetting data. Wazuh's official deployment guide
is at <https://documentation.wazuh.com/current/deployment-options/docker/wazuh-container.html>.
