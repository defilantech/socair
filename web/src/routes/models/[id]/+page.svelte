<script lang="ts">
	import { onMount } from 'svelte';
	import { page } from '$app/state';
	import { model, evidenceURL, type Model, type Document, type AirlockEvent } from '$lib/api';
	import { stageLabel, stageTone } from '$lib/console';
	import ReportView from '$lib/ReportView.svelte';

	let m = $state<Model | null>(null);
	let report = $state<Document | null>(null);
	let events = $state<AirlockEvent[]>([]);
	let error = $state('');

	const files = [
		'report.json',
		'report.dsse.json',
		'report.acceptance.dsse.json',
		'report.conditional.dsse.json',
		'attestation.json',
		'attestation.dsse.json'
	];

	onMount(async () => {
		try {
			const out = await model(page.params.id ?? '');
			m = out.model;
			report = out.report;
			events = out.events;
		} catch (e) {
			error = e instanceof Error ? e.message : String(e);
		}
	});
</script>

<div class="shell">
	{#if error}
		<div class="state failed"><p class="error-title">This model could not be read</p><p>{error}</p></div>
	{:else if m}
		<h2>{m.name}</h2>
		<p class="hint" style="overflow-wrap:anywhere">{m.location} · {m.id}</p>
		<p><span class="tone-{stageTone(m)}">{stageLabel(m)}</span>{#if m.stage_reason} · {m.stage_reason}{/if}</p>
		{#if m.issuer}<p>Issued by {m.issuer} · signed by key {m.signer_key_id?.slice(0, 16)}</p>{/if}
		{#if m.accepted_by}<p>Accepted by {m.accepted_by}: {(m.accepted_surfaces ?? []).join(', ')}, until {m.acceptance_expires}</p>{/if}
		{#if m.next.command}<pre class="cmd">{m.next.command}</pre>{/if}

		{#if report}
			<ReportView {report} />
		{:else}
			<p class="hint">No verified report to show.</p>
		{/if}

		<h2>Evidence</h2>
		<ul>{#each files as f (f)}<li><a href={evidenceURL(m.id, f)} download>{f}</a></li>{/each}</ul>
		<p class="hint">A file that is not part of this entry answers 404.</p>

		<h2>Activity</h2>
		<ul class="ledger">{#each events.slice().reverse() as e, i (i)}<li>{e.ts} · {e.action} · {e.outcome}{e.actor ? ` · ${e.actor}` : ''}{e.detail ? `: ${e.detail}` : ''}</li>{/each}</ul>
	{:else}
		<p class="hint">Reading the model.</p>
	{/if}
</div>
