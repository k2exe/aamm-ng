#!/usr/bin/env bash
#
# Point the release links in README.md at a published release.
#
# GitHub "latest" links ignore pre-releases, and the APK file names include
# the version, so the links cannot be an alias. Run this script after each
# release is published, and commit the change in a documentation pull request.
#
# usage: scripts/update-readme-release.sh <release-tag>
# example: scripts/update-readme-release.sh v0.1.3-beta
set -euo pipefail

if [[ $# -ne 1 ]]; then
    echo "usage: $0 <release-tag>   (for example v0.1.3-beta)" >&2
    exit 2
fi

TAG="$1"

if [[ ! "$TAG" =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-beta)?$ ]]; then
    echo "invalid release tag: $TAG" >&2
    exit 2
fi

REPO_ROOT="$(
    cd "$(dirname "${BASH_SOURCE[0]}")/.."
    pwd
)"

README="${REPO_ROOT}/README.md"
PACKAGE_MAKEFILE="${REPO_ROOT}/packaging/openwrt/Makefile"

PKG_VERSION="$(sed -n 's/^PKG_VERSION:=//p' "$PACKAGE_MAKEFILE")"
PKG_RELEASE="$(sed -n 's/^PKG_RELEASE:=//p' "$PACKAGE_MAKEFILE")"

if [[ -z "$PKG_VERSION" || -z "$PKG_RELEASE" ]]; then
    echo "unable to read package metadata" >&2
    exit 1
fi

tag_version="${TAG#v}"
tag_version="${tag_version%%-*}"

if [[ "$tag_version" != "$PKG_VERSION" ]]; then
    echo "tag version ${tag_version} does not match package version ${PKG_VERSION}" >&2
    echo "run this script from the release commit" >&2
    exit 1
fi

TEMPORARY="$(mktemp)"
trap 'rm -f "$TEMPORARY"' EXIT

sed -E \
    -e "s#releases/(tag|download)/v[0-9]+\.[0-9]+\.[0-9]+(-beta)?#releases/\1/${TAG}#g" \
    -e "s#\[v[0-9]+\.[0-9]+\.[0-9]+(-beta)?\]#[${TAG}]#g" \
    -e "s#AAMM-NG v[0-9]+\.[0-9]+\.[0-9]+(-beta)? is built#AAMM-NG ${TAG} is built#g" \
    -e "s#\[AAMM-NG v[0-9]+\.[0-9]+\.[0-9]+(-beta)? release\]#[AAMM-NG ${TAG} release]#g" \
    -e "s#aamm-ng-[0-9]+\.[0-9]+\.[0-9]+-r[0-9]+-#aamm-ng-${PKG_VERSION}-r${PKG_RELEASE}-#g" \
    "$README" > "$TEMPORARY"

stale="$(
    grep -E 'releases/(tag|download)/v' "$TEMPORARY" |
        grep -v "releases/\(tag\|download\)/${TAG}" || true
)"

if [[ -n "$stale" ]]; then
    echo "README still has links to another release:" >&2
    echo "$stale" >&2
    exit 1
fi

cp "$TEMPORARY" "$README"

echo "README.md now points at ${TAG} (package ${PKG_VERSION}-r${PKG_RELEASE})."
echo "Check the links, then commit the change in a documentation pull request."
