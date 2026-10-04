<script lang="ts">
	// A command the operator runs in the CLI, shown exactly as given: one line
	// that scrolls sideways (never wrapped, so it cannot be mis-copied), a
	// one-line purpose above it, and a Copy button that works without a secure
	// context (falls back to selecting the text and execCommand('copy')).
	let { command, purpose = '' }: { command: string; purpose?: string } = $props();

	let pre = $state<HTMLPreElement | null>(null);
	let status = $state('');
	let timer: ReturnType<typeof setTimeout> | undefined;

	function announce(msg: string) {
		status = msg;
		clearTimeout(timer);
		timer = setTimeout(() => (status = ''), 2500);
	}

	function selectText(): boolean {
		if (!pre) return false;
		const range = document.createRange();
		range.selectNodeContents(pre);
		const sel = window.getSelection();
		if (!sel) return false;
		sel.removeAllRanges();
		sel.addRange(range);
		return true;
	}

	async function copy() {
		try {
			if (navigator.clipboard && window.isSecureContext) {
				await navigator.clipboard.writeText(command);
				announce('Copied');
				return;
			}
		} catch {
			// Fall through to the selection fallback.
		}
		if (selectText() && document.execCommand('copy')) {
			announce('Copied');
		} else {
			announce('Could not copy; the command is selected, copy it with your keyboard');
		}
	}
</script>

<div class="command">
	{#if purpose}<p class="command-purpose">{purpose}</p>{/if}
	<div class="command-row">
		<!-- svelte-ignore a11y_no_noninteractive_tabindex -->
		<pre class="cmd" bind:this={pre} tabindex="0">{command}</pre>
		<button type="button" class="secondary copy" onclick={copy} aria-label={purpose ? `Copy: ${purpose}` : 'Copy command'}>Copy</button>
	</div>
	<p class="command-status" role="status" aria-live="polite">{status}</p>
</div>
