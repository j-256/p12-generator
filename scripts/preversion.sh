#!/bin/bash
set -euo pipefail

readonly RELEASE_BRANCH='main'
readonly RELEASE_REMOTE='origin'

fail() {
    printf 'Error: %s\n' "$*" >&2
    exit 1
}

current_branch="$(git branch --show-current)"
[ "$current_branch" = "$RELEASE_BRANCH" ] ||
    fail "releases must be prepared on ${RELEASE_BRANCH}, not ${current_branch:-detached HEAD}"

worktree_status="$(git status --porcelain)"
[ -z "$worktree_status" ] ||
    fail 'release preparation requires a clean worktree'

remote_ref="refs/remotes/${RELEASE_REMOTE}/${RELEASE_BRANCH}"
git fetch --quiet "$RELEASE_REMOTE" "+refs/heads/${RELEASE_BRANCH}:${remote_ref}" ||
    fail "could not fetch ${RELEASE_REMOTE}/${RELEASE_BRANCH}"

local_head="$(git rev-parse HEAD)"
remote_head="$(git rev-parse "${remote_ref}^{commit}")"
[ "$local_head" = "$remote_head" ] ||
    fail "${RELEASE_BRANCH} and ${RELEASE_REMOTE}/${RELEASE_BRANCH} differ"

npm run release:check
