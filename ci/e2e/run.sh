#!/usr/bin/env bash
# End-to-end container test: a proxy container serving one ecosystem, and a
# client container installing a real package through it.
#
# Usage: ci/e2e/run.sh {pypi|npm|cargo} [image-tag]
#
# Two cases per ecosystem, because "bytes flowed" alone would also pass
# against a proxy that forwarded everything unchecked:
#
#   positive - a real install through the proxy must succeed
#   negative - with min_release_age_days set past any real publication date,
#              every version is too new, and the install must fail
#
# The negative case is driven by release age rather than by a CVE so that it
# does not depend on which advisories happen to exist on the day it runs.
set -euo pipefail

if [ $# -lt 1 ]; then
  echo "usage: run.sh <pypi|npm|cargo> [image-tag]" >&2
  exit 2
fi
ECO="$1"
IMAGE="${2:-scs-proxy:e2e}"
NET="scs-e2e-$ECO-$$"
# A third container owns the network namespace that the stub and the proxy
# both join. Without it the ordering is circular: the proxy must be running
# before the stub can join its namespace, but the PyPI path performs its
# initial advisory sync during startup and refuses to boot when the feed --
# served by that same stub -- is unreachable. Whoever wins that race decides
# whether the run works, which is no way to build a test.
HOLDER="scs-net-$ECO-$$"
PROXY="scs-proxy-$ECO-$$"
STUB="scs-stub-$ECO-$$"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# bubblewrap has to create a user namespace and mount a fresh /proc inside the
# container, for the AI reviewer's collector and for org plugins. Docker's
# default seccomp profile blocks clone(CLONE_NEWUSER), and its masked /proc
# paths break the proc mount. These two relaxations are the minimum that lets
# the sandbox run; they are a property of running the sandbox under Docker in
# a test, not a recommendation for production deployment.
SECURITY_OPTS=(--security-opt seccomp=unconfined --security-opt systempaths=unconfined)

cleanup() {
  docker rm -f "$PROXY" "$STUB" "$HOLDER" >/dev/null 2>&1 || true
  docker network rm "$NET" >/dev/null 2>&1 || true
}
trap cleanup EXIT

start_proxy() {
  local config="$1"
  local stub_verdict="${2:-clean}"
  docker rm -f "$PROXY" "$STUB" "$HOLDER" >/dev/null 2>&1 || true

  # The holder carries the `proxy` alias and the namespace; the stub and the
  # proxy are both tenants of it. Sharing a namespace is what makes the stub
  # loopback to the proxy, which the proxy requires: it refuses a plaintext
  # http:// reviewer URL unless the host is loopback, since an API key would
  # otherwise cross the network in clear text.
  docker run -d --name "$HOLDER" --network "$NET" --network-alias proxy \
    alpine:3.21 sleep infinity >/dev/null

  # Stub before proxy, and waited for: the proxy's own startup reads the
  # advisory feed from it.
  docker run -d --name "$STUB" --network "container:$HOLDER" \
    -e "STUB_VERDICT=$stub_verdict" \
    -v "$HERE/stub_reviewer.py:/stub.py:ro" \
    python:3.13-slim python /stub.py >/dev/null
  for _ in $(seq 1 60); do
    if docker run --rm --network "container:$HOLDER" curlimages/curl:latest \
        -fsS -o /dev/null http://127.0.0.1:9000/healthz 2>/dev/null; then
      break
    fi
    sleep 1
  done

  docker run -d --name "$PROXY" --network "container:$HOLDER" \
    "${SECURITY_OPTS[@]}" \
    -v "$HERE/config/$config:/etc/supply-chain-scanner/config.toml:ro" \
    "$IMAGE" >/dev/null

  for _ in $(seq 1 60); do
    if docker run --rm --network "$NET" curlimages/curl:latest \
        -fsS -o /dev/null http://proxy:8080/healthz 2>/dev/null; then
      echo "proxy healthy ($config)"
      return 0
    fi
    sleep 1
  done
  echo "proxy did not become healthy with $config" >&2
  docker logs "$PROXY" >&2 || true
  return 1
}

client() {
  case "$ECO" in
    pypi)
      docker run --rm --network "$NET" python:3.13-slim sh -c '
        set -e
        pip install --quiet --disable-pip-version-check --root-user-action=ignore \
          --index-url http://proxy:8080/simple/ --trusted-host proxy \
          --no-deps six==1.17.0
        python -c "import six; print(\"six\", six.__version__, \"imported through the proxy\")"
      ' ;;
    npm)
      docker run --rm --network "$NET" node:22-slim sh -c '
        set -e
        cd /tmp && npm init -y >/dev/null 2>&1
        npm install --registry http://proxy:8080/ --no-audit --no-fund --loglevel=error left-pad
        node -e "const f=require(\"/tmp/node_modules/left-pad\"); if (f(\"7\",3,\"0\") !== \"007\") process.exit(1); console.log(\"left-pad works through the proxy\")"
      ' ;;
    cargo)
      docker run --rm --network "$NET" rust:1.88.0-slim sh -c '
        set -e
        mkdir -p /work && cd /work
        cargo init --name probe --vcs none -q .
        printf "cfg-if = \"1\"\n" >> Cargo.toml
        mkdir -p /work/.cargo
        cat > /work/.cargo/config.toml <<CFG
[source.crates-io]
replace-with = "scanner"

[source.scanner]
registry = "sparse+http://proxy:8080/"
CFG
        CARGO_HOME=/work/.cargo cargo fetch
        echo "cfg-if fetched through the proxy"
      ' ;;
    *) echo "unknown ecosystem: $ECO" >&2; return 2 ;;
  esac
}

audit_lines() {
  docker exec "$PROXY" sh -c 'cat /var/log/scanner/audit.jsonl.* 2>/dev/null' || true
}

docker network create "$NET" >/dev/null

echo "=== $ECO: positive case, the install must succeed ==="
start_proxy "$ECO.toml"
# A first fetch triggers the scan, and a cascade that outruns its budget
# answers 429 "SCAN IN PROGRESS - please retry shortly". That is the proxy's
# documented contract, not a failure: the reviews that finished are stored, so
# a retry resumes rather than restarts. pip and cargo do not retry a 429 at
# all and npm gives up quickly, so the retry belongs here. Each attempt is a
# fresh client, exactly as a developer re-running the command would be.
attempt=0
until client; do
  attempt=$((attempt + 1))
  if [ "$attempt" -ge 8 ]; then
    echo "the install never succeeded after $attempt attempts" >&2
    docker logs "$PROXY" 2>&1 | tail -30 >&2
    exit 1
  fi
  echo "attempt $attempt did not succeed yet; the scan may still be running, retrying"
  sleep 15
done
# The audit log is the feature this proxy exists to provide; an install that
# worked but recorded nothing would be a silent hole.
if [ -z "$(audit_lines)" ]; then
  echo "the audit log is empty after a successful install" >&2
  exit 1
fi
echo "audit log recorded $(audit_lines | wc -l) line(s)"
audit_lines | tail -3

echo
echo "=== $ECO: negative case, the gate must refuse ==="
# pypi and npm take their age data from the index and the packument, so the
# release-age gate refuses deterministically there. cargo reads release times
# from the crates.io API, which answers 403 to this proxy and makes the gate
# skip itself — so cargo's negative case comes from the AI gate instead, with
# the stub configured to return a malicious verdict.
case "$ECO" in
  cargo) EXPECT_CODE="ai:malicious"; STUB_VERDICT="malicious" ;;
  *)     EXPECT_CODE="too-new";      STUB_VERDICT="clean" ;;
esac
start_proxy "$ECO-blocked.toml" "$STUB_VERDICT"
if client; then
  echo "the install succeeded while every version should have been too new" >&2
  exit 1
fi
echo "install refused, as expected"
# Prove it was refused *for the configured reason*, not by an unrelated
# failure: a network error would also make the client exit non-zero.
if ! audit_lines | grep -q "$EXPECT_CODE"; then
  echo "no $EXPECT_CODE decision in the audit log; the refusal had another cause" >&2
  audit_lines | tail -5 >&2
  exit 1
fi
echo "audit log attributes the refusal to $EXPECT_CODE"
audit_lines | grep "$EXPECT_CODE" | tail -2

echo
echo "=== $ECO: both cases passed ==="
