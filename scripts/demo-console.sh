#!/usr/bin/env bash
# Build a demo airlock store from real Hugging Face pulls, one model in each
# state the console shows, and print the command that serves it.
#
#   scripts/demo-console.sh [<demo dir>]      (default ~/socair-demo)
#
# The models, each pulled at its current commit:
#   Qwen/Qwen3-0.6B                               approved: every row PASSes
#   hf-internal-testing/tiny-random-LlamaForCausalLM  approved with conditions:
#                                                 a CISO key signs an acceptance
#                                                 of the one NOT_TESTED row
#   katuni4ka/tiny-random-chatglm2                blocked: its config.json
#                                                 auto_map runs the repo's own
#                                                 Python, a Remote code LEAD
#   hf-internal-testing/tiny-random-MistralForCausalLM  staged, not scanned:
#                                                 scan it from the console
#
# It builds socair and the console from this checkout, makes two demo keys
# (an operator who signs reports, an acceptor who signs acceptances), and
# downloads about 1.6 GB, most of it Qwen3-0.6B. Needs go, npm, curl, and jq.
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
D="${1:-$HOME/socair-demo}"
mkdir -p "$D"/{bin,keys,scan}
D="$(cd "$D" && pwd)"
X="$D/bin/socair"
hub="${SOCAIR_HF_ENDPOINT:-https://huggingface.co}"

export SOCAIR_STORE="$D/store" SOCAIR_SCAN_TMP="$D/scan"
if [[ -e "$SOCAIR_STORE" ]]; then
	echo "$SOCAIR_STORE exists: remove it or pass another demo dir" >&2
	exit 1
fi

sha256() {
	if command -v sha256sum >/dev/null 2>&1; then sha256sum; else shasum -a 256; fi
}

echo "== build socair and the console"
(cd "$root" && GOFLAGS=-mod=vendor go build -o "$X" ./cmd/socair)
(cd "$root/web" && npm ci --silent && npm run -s build >/dev/null)

"$X" airlock init "$SOCAIR_STORE" >/dev/null

echo "== demo keys: an operator who signs reports, a CISO who signs acceptances"
"$X" key gen --out "$D/keys/operator" --issuer "Acme ML Platform" >/dev/null
"$X" airlock trust add "$D/keys/operator.pub" --name "Acme ML Platform" >/dev/null
"$X" key gen --out "$D/keys/ciso" --issuer "Jane Doe, CISO" >/dev/null
"$X" airlock trust add --acceptor "$D/keys/ciso.pub" >/dev/null

# A one-entry known-bad list, so that row can PASS on the approved example.
printf '%s  demo-known-bad-entry\n' "$(printf 'socair demo known-bad' | sha256 | cut -d' ' -f1)" >"$D/denylist.txt"

# pull <repo> [pull flags...]: pull a whole repo at its current commit and
# print where it was staged.
pull() {
	local repo=$1 rev
	shift
	rev=$(curl -fsS "$hub/api/models/$repo/revision/main" | jq -r .sha)
	echo "== pull $repo at $rev" >&2
	"$X" airlock pull --repo "$repo" --revision "$rev" "$@" | sed -n 's/^staged at //p'
}

# scan_sign <staged dir> [VAR=value...]: scan with the pull's provenance into
# the staging entry, where the console reads it, and sign the report.
scan_sign() {
	local staged=$1 e
	shift
	e=$(dirname "$staged")
	env SOCAIR_PROVENANCE="$e/provenance.json" "$@" "$X" scan "$staged" >"$e/report.json"
	"$X" sign --key "$D/keys/operator.key" --report "$e/report.json" >/dev/null
	echo "   $(jq -r '.promotion_authorization.state' "$e/report.json")$(jq -r '[.checks[] | select(.status != "PASS") | "\(.name) \(.status)"] | if length > 0 then ": " + join(", ") else "" end' "$e/report.json")" >&2
}

# Approved: every row PASSes, so the signed attestation crosses as it is.
q=$(pull Qwen/Qwen3-0.6B)
scan_sign "$q" SOCAIR_DENYLIST="$D/denylist.txt"
"$X" airlock promote "$q" --attestation "$(dirname "$q")/report.dsse.json" >/dev/null

# Approved with conditions: with no known-bad list that row is NOT_TESTED, and
# the CISO signs an acceptance of exactly that gap, until the rescan date.
l=$(pull hf-internal-testing/tiny-random-LlamaForCausalLM --exclude onnx/)
scan_sign "$l"
e=$(dirname "$l")
"$X" accept --attestation "$e/report.dsse.json" --key "$D/keys/ciso.key" --by "Jane Doe, CISO" \
	--expires "$(jq -r '.header.rescan_due' "$e/report.json")" --store "$SOCAIR_STORE" >/dev/null
"$X" sign --key "$D/keys/operator.key" --attestation "$e/report.dsse.json" \
	--acceptance "$e/report.acceptance.dsse.json" --store "$SOCAIR_STORE" >/dev/null
"$X" airlock promote "$l" --attestation "$e/report.conditional.dsse.json" >/dev/null

# Blocked: the repo ships Python that config.json's auto_map would run under
# trust_remote_code. A LEAD, which no acceptance clears.
c=$(pull katuni4ka/tiny-random-chatglm2 --exclude runs/ --exclude training_args.bin)
scan_sign "$c"

# Staged, not scanned: scan it from the console.
pull hf-internal-testing/tiny-random-MistralForCausalLM --exclude onnx/ >/dev/null

cat <<EOF

Demo store ready. Serve the console:

  $X serve --store $SOCAIR_STORE --web $root/web/build

and open http://127.0.0.1:8080. The demo keys are in $D/keys.
EOF
