<script lang="ts">
	import { onMount } from 'svelte';
	import { airlockLog, type AirlockEvent } from '$lib/api';
	import Command from '$lib/Command.svelte';
	import EventList from '$lib/EventList.svelte';

	let events = $state<AirlockEvent[] | null>(null);
	let error = $state('');
	let action = $state('');

	onMount(async () => {
		try {
			events = await airlockLog();
		} catch (e) {
			events = null;
			error = e instanceof Error ? e.message : String(e);
		}
	});

	const shown = $derived((events ?? []).filter((e) => !action || e.action === action).slice().reverse());
</script>

<svelte:head><title>Activity · Socair</title></svelte:head>

<h1>Activity</h1>
<p class="lede">The airlock's log, newest first. It is hash-chained: check it, and record the head somewhere this host cannot rewrite.</p>
<Command command="socair airlock log --verify" purpose="Verifies the log's hash chain" />

<div class="filter">
	<label for="action-filter">Show</label>
	<select id="action-filter" bind:value={action}>
		<option value="">all actions</option>
		{#each ['pull', 'ingest', 'trust', 'promote', 'refuse'] as a (a)}<option value={a}>{a}</option>{/each}
	</select>
</div>

{#if error}
	<div class="state failed" role="alert"><p class="error-title">The log could not be read</p><p>{error}</p></div>
{:else if events === null}
	<p class="meta" role="status">Reading the log.</p>
{:else if shown.length === 0}
	<p class="meta">{action ? `No ${action} entries in the log.` : 'The log is empty.'}</p>
{:else}
	<EventList events={shown} hash />
{/if}
