#!/usr/bin/env bash
# Check that every commit in <base>..<head> carries a Developer Certificate of
# Origin sign-off by its author (https://developercertificate.org/):
#
#   Signed-off-by: <author name> <author email>
#
# `git commit -s` adds the line. Merge commits and bot authors (dependabot and
# the like, whose "[bot]" accounts sign off under another address) are exempt.
#
#   scripts/check-dco.sh <base> <head>
set -euo pipefail

base="${1:?usage: check-dco.sh <base> <head>}"
head="${2:?usage: check-dco.sh <base> <head>}"

missing=0
while IFS= read -r c; do
	name=$(git show -s --format=%an "$c")
	email=$(git show -s --format=%ae "$c")
	if [[ "$name" == *"[bot]" ]]; then
		continue
	fi
	want="signed-off-by: $name <$email>"
	if ! git show -s --format=%B "$c" | tr '[:upper:]' '[:lower:]' | grep -qxF -- "$(tr '[:upper:]' '[:lower:]' <<<"$want")"; then
		echo "::error::$(git show -s --format='%h %s' "$c"): no \"Signed-off-by: $name <$email>\" line"
		missing=1
	fi
done < <(git rev-list --no-merges "$base..$head")

if [[ "$missing" == 1 ]]; then
	cat <<'HELP'
Every commit needs a DCO sign-off by its author (see CONTRIBUTING.md). Add it
to the commits in this pull request and force-push:

  git rebase --signoff <base branch>
  git push --force-with-lease
HELP
	exit 1
fi
echo "every commit in $base..$head is signed off by its author"
