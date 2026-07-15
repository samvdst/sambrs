#!/usr/bin/env bash
set -euo pipefail

cd -- "$(dirname -- "${BASH_SOURCE[0]}")"

fail() {
  echo "release: $*" >&2
  exit 1
}

[[ $(git branch --show-current) == main ]] || fail "not on main"
[[ -z $(git status --porcelain) ]] || fail "working tree is not clean"

git fetch --quiet origin
[[ $(git rev-parse HEAD) == $(git rev-parse origin/main) ]] ||
  fail "main does not match origin/main"

package_id=$(cargo pkgid)
version=${package_id##*@}
version=${version##*#}
tag="v$version"

if git rev-parse --quiet --verify "refs/tags/$tag" >/dev/null; then
  fail "tag $tag already exists"
fi

read -r -p "Do you want to release version $version? [y/N] " answer
case "$answer" in
  y | Y | yes | YES) ;;
  *) echo "Release cancelled."; exit 0 ;;
esac

git tag --annotate "$tag" --message "Release $version"
if ! git push origin "$tag"; then
  git tag --delete "$tag" >/dev/null
  fail "failed to push $tag"
fi

echo "Pushed $tag; the release workflow will publish it."
