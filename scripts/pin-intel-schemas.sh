#!/bin/sh
# Pins Intel's shared schema and wording files at a tag (docs/project_structure.md §2.3,
# git-tag distribution). Downloads by the tag's commit, which cannot move, and
# writes intel-schemas/PINNED and intel-schemas/SHA256SUMS. Never edit the
# pinned files by hand; `make schemas-check` (part of verify) enforces this.
#
# Usage: scripts/pin-intel-schemas.sh <tag>     e.g. v0.1.0-next.0
set -eu

TAG="${1:?usage: $0 <tag>}"
REPO="SoroSentinel/Sorosentinel-intel"
OUT="$(cd "$(dirname "$0")/.." && pwd)/intel-schemas"
FILES="schemas/vectors/canonical_keys.json schemas/vectors/snapshot_signing.json schemas/jsonschema/Snapshot.json schemas/jsonschema/AnalysisResult.json wording/vectors/render.json wording/blocklist.yaml"

COMMIT=$(git ls-remote "https://github.com/$REPO" "refs/tags/$TAG^{}" | cut -f1)
[ -n "$COMMIT" ] || COMMIT=$(git ls-remote "https://github.com/$REPO" "refs/tags/$TAG" | cut -f1)
case "$COMMIT" in
  [0-9a-f][0-9a-f][0-9a-f][0-9a-f]*) ;;
  *) echo "tag $TAG not found in $REPO" >&2; exit 1 ;;
esac

rm -rf "$OUT"
mkdir -p "$OUT"
for f in $FILES; do
  dest="$OUT/$(basename "$f")"
  curl -fsSL --max-time 30 --max-filesize 1048576 "https://raw.githubusercontent.com/$REPO/$COMMIT/$f" -o "$dest"
done
printf 'repo %s\ntag %s\ncommit %s\n' "$REPO" "$TAG" "$COMMIT" > "$OUT/PINNED"
(cd "$OUT" && for f in $FILES; do shasum -a 256 "$(basename "$f")"; done > SHA256SUMS)
echo "pinned $REPO $TAG ($COMMIT) into intel-schemas/"
