#!/bin/sh
set -eu

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
source_dir=${WIKI_SOURCE_DIR:-"$repo_root/docs/wiki"}
repository=${GITHUB_REPOSITORY:-georgestarcher/dmarcgo}
remote_url=${WIKI_REMOTE_URL:-"https://github.com/${repository}.wiki.git"}
target_branch=${WIKI_BRANCH:-}
source_sha=${WIKI_SOURCE_SHA:-$(git -C "$repo_root" rev-parse HEAD)}

python3 "$repo_root/scripts/check_wiki.py"

work_dir=$(mktemp -d)
cleanup() {
    rm -rf "$work_dir"
}
trap cleanup EXIT HUP INT TERM

if [ -n "${GITHUB_TOKEN:-}" ]; then
    askpass="$work_dir/askpass.sh"
    {
        printf '%s\n' '#!/bin/sh'
        printf '%s\n' 'case "$1" in'
        printf '%s\n' '  *Username*) printf "%s\n" "x-access-token" ;;'
        printf '%s\n' '  *Password*) printf "%s\n" "$GITHUB_TOKEN" ;;'
        printf '%s\n' 'esac'
    } >"$askpass"
    chmod 700 "$askpass"
    export GIT_ASKPASS="$askpass"
    export GIT_TERMINAL_PROMPT=0
fi

wiki_dir="$work_dir/wiki"
if [ -n "$target_branch" ]; then
    if ! git clone --quiet --branch "$target_branch" --single-branch "$remote_url" "$wiki_dir"; then
        printf '%s\n' "unable to clone wiki branch ${target_branch}" >&2
        printf '%s\n' "if this is the first publication, create one temporary Home page in GitHub's wiki UI and retry" >&2
        exit 1
    fi
else
    if ! git clone --quiet --single-branch "$remote_url" "$wiki_dir"; then
        printf '%s\n' "unable to clone the wiki repository" >&2
        printf '%s\n' "if this is the first publication, create one temporary Home page in GitHub's wiki UI and retry" >&2
        exit 1
    fi
    target_branch=$(git -C "$wiki_dir" branch --show-current)
    if [ -z "$target_branch" ]; then
        printf '%s\n' "unable to determine the wiki's default branch" >&2
        exit 1
    fi
fi

git -C "$wiki_dir" rm -r --quiet --ignore-unmatch .
find "$source_dir" -maxdepth 1 -type f -name '*.md' -exec cp {} "$wiki_dir"/ \;

git -C "$wiki_dir" add --all
if git -C "$wiki_dir" diff --cached --quiet; then
    printf '%s\n' "wiki already matches canonical source"
    exit 0
fi

git -C "$wiki_dir" config user.name "github-actions[bot]"
git -C "$wiki_dir" config user.email "41898282+github-actions[bot]@users.noreply.github.com"
git -C "$wiki_dir" commit --quiet -m "Publish wiki from ${source_sha}"
git -C "$wiki_dir" push --quiet origin "HEAD:${target_branch}"
printf '%s\n' "published wiki from ${source_sha}"
