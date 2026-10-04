<script lang="ts">
	import { onMount } from 'svelte';
	import { airlockLog, type AirlockEvent } from '$lib/api';

	let events = $state<AirlockEvent[] | null>(null);
	let error = $state('');
	let action = $state('');

	onMount(async () => {
		try {
			events = await airlockLog();
		} catch (e) {
			error = e instanceof Error ? e.message : String(e);
		}
	});

	const shown = $derived((events ?? []).filter((e) => !action || e.action === action).slice().reverse());
</script>

<div class="shell">
	<h2>Activity</h2>
	{#if error}<div class="state failed"><p class="error-title">The log could not be read</p><p>{error}</p></div>{/if}
	<label>Action <select bind:value={action}><option value="">all</option>{#each ['pull', 'ingest', 'trust', 'promote', 'refuse'] as a (a)}<option value={a}>{a}</option>{/each}</select></label>
	<p class="hint">The log is hash-chained. Check it, and record the head somewhere this host cannot rewrite:</p>
	<pre class="cmd">socair airlock log --verify</pre>
	<ul class="ledger">{#each shown as e, i (i)}<li>{e.ts} · {e.action} · {e.outcome}{e.actor ? ` · ${e.actor}` : ''}{e.sha256 ? ` · ${e.sha256.slice(0, 12)}` : ''}{e.detail ? `: ${e.detail}` : ''}</li>{/each}</ul>
</div>
