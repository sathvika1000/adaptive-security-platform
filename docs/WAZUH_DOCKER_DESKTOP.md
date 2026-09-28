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

For a live end-to-end check, first generate two permitted authentication
events on an endpoint that Wazuh monitors, with the same target account and
host within 15 minutes. Confirm two different IDs appear in the manager's
`/var/ossec/logs/alerts/alerts.json`, then check the platform with the same
key:

```sh
docker compose -p asp-wazuh -f ../wazuh-docker/single-node/docker-compose.yml \
  -f deploy/wazuh-loopback.yaml exec wazuh.manager \
  sh -c 'tail -n 2 /var/ossec/logs/alerts/alerts.json'
curl -fsS -H "X-API-Key: $ASP_API_KEY" http://127.0.0.1:8000/v1/incidents
```

Run the `docker compose ... exec` command from the platform repository (the
first file's relative paths resolve against the Wazuh directory). The two
alerts must have a recognized authentication group, a user (`dstuser` or
`srcuser`), and an agent name for this POC's correlation contract. Manager
startup alone does not create that pair. An empty incident list means to
inspect the actual alert fields and forwarder logs before changing rules.

## Back up the platform database

From the platform repository, keep the API running and create a SQLite
snapshot in its named volume. Copy both snapshot files to the Mac before
relying on the backup:

```sh
python3 scripts/backup_docker.py
```

The command creates a snapshot, verifies it inside Docker, copies both files
to a new private directory in ignored `artifacts/`, and verifies the host
copy's digest, SQLite integrity, and table counts. Its last lines print the
verified paths. It does not remove the original snapshot from the Docker
volume or rotate earlier backups. A manually controlled equivalent is:

```sh
backup_name="security-$(date -u +%Y%m%dT%H%M%SZ).db"
mkdir -p artifacts
docker exec adaptive-security-platform-platform-1 \
  python -m adaptive_security.backup create /data/security.db "/data/$backup_name"
docker exec adaptive-security-platform-platform-1 \
  python -m adaptive_security.backup verify "/data/$backup_name"
docker cp "adaptive-security-platform-platform-1:/data/$backup_name" \
  "artifacts/$backup_name"
docker cp "adaptive-security-platform-platform-1:/data/$backup_name.manifest.json" \
  "artifacts/$backup_name.manifest.json"
```

Keep the two copied files together and compare the output of
`shasum -a 256 "artifacts/$backup_name"` with the manifest's `sha256` before moving them to
protected storage. The `artifacts/` directory is ignored by Git. The snapshot
includes events, incidents, aliases, transitions, baselines, and signals; it
does not include Wazuh's indexer, manager, or forwarder cursor volumes. Avoid
deleting the live database or its volume as part of the backup procedure.

## Stop and restart

```sh
docker compose -f compose.yaml -f compose.wazuh.yaml down
docker compose -p asp-wazuh -f ../wazuh-docker/single-node/docker-compose.yml \
  -f deploy/wazuh-loopback.yaml down
```

These commands preserve the SQLite, alert, and cursor volumes. Do not append
`-v` unless intentionally resetting data. Wazuh's official deployment guide
is at <https://documentation.wazuh.com/current/deployment-options/docker/wazuh-container.html>.
