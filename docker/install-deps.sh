#!/bin/sh
# Extraction tool-chain for unblob. Package list adapted from unblob 26.6.4's
# install-deps.sh (MIT, ONEKEY). Everything comes from Debian except
# sasquatch (vendor-patched squashfs), which is pinned by SHA-256.
set -eu

printf "deb http://deb.debian.org/debian bookworm-backports main\n" > /etc/apt/sources.list.d/backports.list
apt-get update
apt-get install --no-install-recommends -y \
    android-sdk-libsparse-utils \
    ca-certificates \
    curl \
    e2fsprogs \
    erofs-utils \
    libmagic1 \
    lz4 \
    lziprecover \
    lzop \
    p7zip-full \
    partclone \
    unar \
    upx \
    xz-utils \
    zstd

SASQUATCH_TAG=sasquatch-v4.5.1-6
arch="$(dpkg --print-architecture)"
case "$arch" in
    amd64) sha=efbc92bd27594e01211e1b582f105a463a0017360a0746a93de3f283906ade95 ;;
    arm64) sha=28e57a4ff545da32a65c3e061ff8a51e5ebaa5d170985c49f0b3eef08923476e ;;
    *) echo "unsupported architecture: $arch" >&2; exit 1 ;;
esac
curl -fsSL -o /tmp/sasquatch.deb "https://github.com/onekey-sec/sasquatch/releases/download/${SASQUATCH_TAG}/sasquatch_1.0_${arch}.deb"
echo "${sha}  /tmp/sasquatch.deb" | sha256sum -c -
dpkg -i /tmp/sasquatch.deb
rm -f /tmp/sasquatch.deb

apt-get purge -y curl
apt-get autoremove -y
rm -rf /var/lib/apt/lists/*
