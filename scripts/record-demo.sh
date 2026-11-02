#!/usr/bin/env bash
# Record the README's terminal demo as a GIF.
#
#   scripts/record-demo.sh [<out.gif>]      (default docs/demo/intake.gif)
#
# Two models go through the same intake:
#   qwen2-tiny        the detection benchmark's dir-remote-code-tiny-qwen2
#                     case, shaped like the October 2026 Hugging Face miner
#                     campaign: a repo posing as a tiny Qwen2 checkpoint whose
#                     auto_map names a module that runs at import. Defanged:
#                     its stand-in payload only builds a string. The benchmark
#                     test writes it (SOCAIR_BENCHMARK_CORPUS), so the demo
#                     scans the benchmark's own bytes.
#   Qwen/Qwen3-0.6B   pulled through the airlock at a pinned commit (about
#                     1.5 GB, the only network use).
# Both reports are signed with a fresh demo key; the first is refused at
# promotion, the second is promoted and verified.
#
# Needs go, jq, asciinema 3, and agg. Everything else lands in a temp dir.
# The recording caps idle time at 4 seconds, so the download is shortened.
# SOCAIR_DEMO_FONT_DIR points agg at a font directory (the GIF in the repo
# uses JetBrains Mono).
set -euo pipefail

revision=c1899de289a04d12100db370d81485cdf75e47ca
digest=fbb2e51d2156914d13091c694e8ac226bedc3022c587f31f72ca8831304fb199

# The recorded commands are shown as typed, $D included; eval expands them.
# shellcheck disable=SC2016
if [ "${1:-}" = "--play" ]; then
	# The recorded session: runs in the work dir, with socair on PATH.
	say() {
		printf '\033[90m# %s\033[0m\n' "$@"
		sleep 1.5
	}
	run() {
		local cmd=$1 pause=${2:-1.5} i
		printf '\033[32m$\033[0m '
		for ((i = 0; i < ${#cmd}; i++)); do
			printf '%s' "${cmd:i:1}"
			sleep 0.015
		done
		sleep 0.5
		printf '\n'
		eval "$cmd" || true
		sleep "$pause"
	}
	cls() { printf '\033[2J\033[H'; }

	cls
	say "A repo shaped like the October 2026 Hugging Face miner campaign: it poses as a tiny" \
		"Qwen2 checkpoint, and its config tells the loader to import its Python. Defanged, from" \
		"Socair's detection benchmark."
	run 'ls qwen2-tiny'
	run 'socair scan qwen2-tiny > tiny.json' 3
	run "jq -r '.checks[] | select(.status == \"LEAD\") | .evidence' tiny.json" 4

	cls
	say "A real model, pulled through the airlock at a pinned commit."
	run "socair airlock pull --repo Qwen/Qwen3-0.6B --revision $revision" 3
	run "D=$digest" 0.5
	run 'SOCAIR_PROVENANCE=airlock/incoming/$D/provenance.json socair scan airlock/incoming/$D/Qwen3-0.6B > qwen.json' 0.5
	run "jq -r '(.checks[] | \"\\(.status)  \\(.name)\"), \"promotion: \\(.promotion_authorization.state)\"' qwen.json" 4

	cls
	say "Sign both reports with your own key, and trust it at the airlock."
	run 'socair key gen --out operator --issuer "Acme ML Platform" && socair airlock trust add operator.pub' 1
	run 'socair sign --key operator.key --report tiny.json && socair sign --key operator.key --report qwen.json' 2

	cls
	say "Promote both. Only one crosses into the clean store, and anyone can verify it offline."
	run 'socair airlock promote qwen2-tiny --attestation tiny.dsse.json' 4
	run 'socair airlock promote airlock/incoming/$D/Qwen3-0.6B --attestation qwen.dsse.json' 2
	run 'socair verify qwen.dsse.json --trusted operator.pub --artifact airlock/clean/$D/Qwen3-0.6B' 3
	exit 0
fi

root=$(cd "$(dirname "$0")/.." && pwd)
out=${1:-$root/docs/demo/intake.gif}
case "$out" in /*) ;; *) out=$PWD/$out ;; esac
for tool in go jq asciinema agg; do
	command -v "$tool" >/dev/null || { echo "record-demo: $tool is required" >&2; exit 1; }
done

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/bin" "$work/demo"
(cd "$root" && go build -o "$work/bin/socair" ./cmd/socair)
(cd "$root" && SOCAIR_BENCHMARK_CORPUS="$work/corpus" go test ./internal/benchmark -run '^TestDetectionBenchmark$' -count=1 >/dev/null)
cp -R "$work/corpus/dir-remote-code-tiny-qwen2/model" "$work/demo/qwen2-tiny"

cd "$work/demo"
export PATH="$work/bin:$PATH" SOCAIR_STORE=airlock
socair airlock init >/dev/null
asciinema rec --quiet --headless --window-size 100x26 --idle-time-limit 4 \
	-c "bash $root/scripts/record-demo.sh --play" "$work/demo.cast"

# The demo must show what its caption says. The cast's output events, joined,
# are the session's output stream.
tail -n +2 "$work/demo.cast" | jq -j 'select(.[1] == "o") | .[2]' > "$work/demo.out"
for want in 'promotion: withheld' 'imported with trust_remote_code' 'promotion: authorized' \
	'promotion refused' "promoted $digest" 'verified: issued by Acme ML Platform'; do
	grep -qF "$want" "$work/demo.out" || { echo "record-demo: the recording does not show: $want" >&2; exit 1; }
done

theme=0f2333,e7eef1,0b1a26,f2877a,4cd3ae,e9b65a,7fb3e0,c9a0dc,7fd6d0,e7eef1,8fa3af,f6a499,6ee0c0,f0c97e,9cc6ea,d8b8e6,9fe3de,f4f7f8
font_args=(--font-family "JetBrains Mono,Menlo,DejaVu Sans Mono")
[ -n "${SOCAIR_DEMO_FONT_DIR:-}" ] && font_args+=(--font-dir "$SOCAIR_DEMO_FONT_DIR")
mkdir -p "$(dirname "$out")"
agg --quiet --theme "$theme" "${font_args[@]}" --font-size 16 --idle-time-limit 4 --last-frame-duration 8 \
	"$work/demo.cast" "$out"
echo "wrote $out"
