#!/usr/bin/env bash
#
# synology-tarballs.sh — build per-arch tsctl images and save each as a
# docker-archive tarball tagged with a BARE `tsctl:<ver>` (no registry / no
# `localhost/` prefix), so the Synology Container Manager compose
# (`image: tsctl:<ver>` + `pull_policy: never`) loads them with NO registry
# contact. Output: dist/tsctl-<ver>-linux-<arch>-image.tar.gz (dist is gitignored).
#
# The Dockerfile cross-compiles on $BUILDPLATFORM, so an arm64 host builds the
# linux/amd64 image with no qemu (the distroless layer only copies the binary).
#
# Why the rewrite: podman normalizes a bare `-t tsctl:<ver>` to
# `localhost/tsctl:<ver>` and records THAT in the archive's RepoTags — which would
# not match `image: tsctl:<ver>`. We rewrite RepoTags back to the bare name so the
# loaded image matches the compose. (Engine-agnostic: podman or docker.)
#
# Usage:   scripts/synology-tarballs.sh [VERSION]
# Env:     ARCHES  default "amd64 arm64"   (e.g. ARCHES=arm64 for an ARM NAS only)
#          IMAGE   default "tsctl"         (bare image name; no registry)
set -euo pipefail
cd "$(dirname "$0")/.."

VERSION="${1:-${VERSION:-$(git describe --tags --always --dirty 2>/dev/null || echo dev)}}"
ARCHES="${ARCHES:-amd64 arm64}"
IMAGE="${IMAGE:-tsctl}"
ENGINE="$(command -v podman || command -v docker || true)"
[ -n "${ENGINE}" ] || { echo "!! need podman or docker on PATH"; exit 1; }

mkdir -p dist
echo ">> tsctl Synology tarballs  ${IMAGE}:${VERSION}  arches=[${ARCHES}]  engine=$(basename "${ENGINE}")"

for arch in ${ARCHES}; do
  out="dist/tsctl-${VERSION}-linux-${arch}-image.tar.gz"
  raw="$(mktemp -t tsctl-img-XXXXXX).tar"
  echo ">> build linux/${arch}"
  "${ENGINE}" build --platform "linux/${arch}" -t "${IMAGE}:${VERSION}" \
    --build-arg VERSION="${VERSION}" .
  echo ">> save + rewrite RepoTags -> bare ${IMAGE}:${VERSION}"
  "${ENGINE}" save --format docker-archive -o "${raw}" "${IMAGE}:${VERSION}"
  # Rewrite ONLY manifest.json's RepoTags to the bare name; every other archive
  # member is copied through verbatim (name/size/mode preserved), then gzip.
  RAW="${raw}" OUT="${out}" BARE="${IMAGE}:${VERSION}" python3 - <<'PY'
import gzip, io, json, os, tarfile
raw, out, bare = os.environ["RAW"], os.environ["OUT"], os.environ["BARE"]
buf = io.BytesIO()
with tarfile.open(raw, "r") as tin, tarfile.open(fileobj=buf, mode="w") as tout:
    for m in tin.getmembers():
        body = tin.extractfile(m).read() if m.isfile() else b""
        if m.name == "manifest.json":
            man = json.loads(body)
            for entry in man:
                entry["RepoTags"] = [bare]
            body = json.dumps(man).encode()
            info = tarfile.TarInfo(m.name); info.size = len(body); info.mode = 0o644
            tout.addfile(info, io.BytesIO(body))
        elif m.isfile():
            tout.addfile(m, io.BytesIO(body))
        else:
            tout.addfile(m)
with gzip.open(out, "wb") as g:
    g.write(buf.getvalue())
os.remove(raw)
print("   wrote", out)
PY
done

echo ">> done:"
ls -lh dist/tsctl-"${VERSION}"-linux-*-image.tar.gz
