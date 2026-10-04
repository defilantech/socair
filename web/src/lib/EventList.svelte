<script lang="ts">
	import type { AirlockEvent } from './api';
	import { eventTone } from './console';
	import { shortTime } from './when';

	// Log lines as the engine wrote them, newest first: time, action, outcome
	// (a refusal red, a conditional promotion amber, anything else neutral),
	// then who and what. `hash` adds the entry's short id.
	let { events, hash = false }: { events: AirlockEvent[]; hash?: boolean } = $props();
</script>

<ol class="ledger">
	{#each events as e, i (i)}
		<li>
			<time class="ledger-time" datetime={e.ts} title={e.ts}>{shortTime(e.ts)}</time>
			<span class="ledger-what">
				<span class="ledger-action">{e.action}</span>
				<span class="status tone-{eventTone(e)}">{e.outcome}</span>
				{#if e.actor}<span class="ledger-actor">{e.actor}</span>{/if}
				{#if hash && e.sha256}<span class="mono" title={e.sha256}>{e.sha256.slice(0, 12)}</span>{/if}
			</span>
			{#if e.detail || e.repo}<span class="ledger-detail">{e.repo ? `${e.repo}${e.detail ? ': ' : ''}` : ''}{e.detail ?? ''}</span>{/if}
		</li>
	{/each}
</ol>
