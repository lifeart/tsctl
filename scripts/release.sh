#!/usr/bin/env bash
#
# release.sh — build tsctl release artifacts: static binaries + a multi-arch
# container image with a FULLY-QUALIFIED name (so podman never adds its
# "localhost/" prefix). Engine-agnostic (podman or docker buildx).
#
# Usage:
#   scripts/release.sh [VERSION]
#
# Env overrides:
#   REGISTRY   default ghcr.io
#   REPO       default lifeart/tsctl
#   IMAGE      default $REGISTRY/$REPO        (the qualified name — no localhost/)
#   PLATFORMS  default linux/amd64,linux/arm64
#   PUSH       default 0   (set 1 to push the image/manifest to the registry)
#   BINARIES   default 1   (set 0 to skip the cross-compiled binaries)
#   IMAGE_BUILD default 1  (set 0 to skip the container image)
#
# Examples:
#   scripts/release.sh v0.1.0                 # binaries + local multi-arch image
#   PUSH=1 scripts/release.sh v0.1.0          # also push to ghcr.io
#   PLATFORMS=linux/amd64 scripts/release.sh  # amd64-only (e.g. an Intel NAS)

set -euo pipefail
cd "$(dirname "$0")/.."

REGISTRY="${REGISTRY:-ghcr.io}"
REPO="${REPO:-lifeart/tsctl}"
IMAGE="${IMAGE:-$REGISTRY/$REPO}"
PLATFORMS="${PLATFORMS:-linux/amd64,linux/arm64}"
PUSH="${PUSH:-0}"
BINARIES="${BINARIES:-1}"
IMAGE_BUILD="${IMAGE_BUILD:-1}"

# Version: explicit arg > $VERSION env > git describe > "dev".
VERSION="${1:-${VERSION:-$(git describe --tags --always --dirty 2>/dev/null || echo dev)}}"
LDFLAGS="-s -w -X main.version=${VERSION}"

echo ">> tsctl release ${VERSION}"
echo ">> image=${IMAGE}  platforms=${PLATFORMS}  push=${PUSH}"

# --- 1) static, CGO-free, version-stamped binaries (engine-independent) -------
if [ "${BINARIES}" = "1" ]; then
  rm -rf dist && mkdir -p dist
  # The linux targets follow $PLATFORMS; add macOS for local convenience.
  targets="$(echo "${PLATFORMS}" | tr ',' ' ') darwin/arm64 darwin/amd64"
  for p in ${targets}; do
    os="${p%%/*}"; arch="${p##*/}"
    out="dist/tsctl-${VERSION}-${os}-${arch}"
    echo ">> build ${out}"
    CGO_ENABLED=0 GOOS="${os}" GOARCH="${arch}" GOTOOLCHAIN=auto \
      go build -trimpath -ldflags "${LDFLAGS}" -o "${out}" ./cmd/tsctl
  done
  ( cd dist && (sha256sum tsctl-* 2>/dev/null || shasum -a 256 tsctl-*) > SHA256SUMS )
  echo ">> binaries + SHA256SUMS in ./dist"
fi

# --- 2) multi-arch container image, properly named (no localhost/ prefix) -----
if [ "${IMAGE_BUILD}" != "1" ]; then
  echo ">> IMAGE_BUILD=0, skipping container image"; exit 0
fi

ENGINE="$(command -v podman || command -v docker || true)"
if [ -z "${ENGINE}" ]; then
  echo ">> no podman/docker found; binaries are in ./dist"; exit 0
fi
engine_name="$(basename "${ENGINE}")"
echo ">> engine=${engine_name}"

if [ "${engine_name}" = "podman" ]; then
  # Build a multi-arch MANIFEST LIST named with the qualified IMAGE. Because the
  # name already has a registry (ghcr.io/...), podman does NOT prepend localhost/.
  "${ENGINE}" manifest rm "${IMAGE}:${VERSION}" 2>/dev/null || true
  "${ENGINE}" build --platform "${PLATFORMS}" --manifest "${IMAGE}:${VERSION}" \
    --build-arg VERSION="${VERSION}" .
  "${ENGINE}" tag "${IMAGE}:${VERSION}" "${IMAGE}:latest"
  # Belt-and-suspenders: if a stray localhost/ image exists, retag it cleanly.
  if "${ENGINE}" image exists "localhost/${REPO}:${VERSION}" 2>/dev/null; then
    "${ENGINE}" tag "localhost/${REPO}:${VERSION}" "${IMAGE}:${VERSION}"
  fi
  if [ "${PUSH}" = "1" ]; then
    "${ENGINE}" manifest push --all "${IMAGE}:${VERSION}" "docker://${IMAGE}:${VERSION}"
    "${ENGINE}" manifest push --all "${IMAGE}:latest"     "docker://${IMAGE}:latest"
  fi
else
  # docker buildx: multi-arch needs --push (the daemon can't --load a manifest
  # list). For a local single-arch load, pass PLATFORMS=linux/<hostarch>.
  out_flag="--load"
  case "${PLATFORMS}" in *,*) out_flag="--push" ;; esac
  [ "${PUSH}" = "1" ] && out_flag="--push"
  if [ "${out_flag}" = "--push" ] && [ "${PUSH}" != "1" ]; then
    echo "!! docker buildx can't --load a multi-arch image; set PUSH=1 or PLATFORMS=linux/<arch>"; exit 1
  fi
  "${ENGINE}" buildx build --platform "${PLATFORMS}" \
    -t "${IMAGE}:${VERSION}" -t "${IMAGE}:latest" \
    --build-arg VERSION="${VERSION}" "${out_flag}" .
fi

echo ">> image: ${IMAGE}:${VERSION} (+ :latest)"
[ "${PUSH}" = "1" ] && echo ">> pushed to ${REGISTRY}" || echo ">> built locally (set PUSH=1 to publish)"
