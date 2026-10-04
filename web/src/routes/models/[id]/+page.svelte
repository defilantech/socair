<script lang="ts">
	import { page } from '$app/state';
	import { model, evidenceURL, type Model, type Document, type AirlockEvent } from '$lib/api';
	import {
		stageLabel,
		stageTone,
		reasonBeyondLabel,
		acceptedLine,
		nextPurpose,
		isApprovedList
	} from '$lib/console';
	import { navSection } from '$lib/nav.svelte';
	import ReportView from '$lib/ReportView.svelte';
	import Command from '$lib/Command.svelte';
	import EventList from '$lib/EventList.svelte';
	import When from '$lib/When.svelte';

	let m = $state<Model | null>(null);
	let report = $state<Document | null>(null);
	let events = $state<AirlockEvent[]>([]);
	let evidence = $state<string[]>([]);
	let error = $state('');

	$effect(() => {
		const id = page.params.id ?? '';
		m = null;
		report = null;
		events = [];
		evidence = [];
		error = '';
		const ctl = new AbortController();
		(async () => {
			try {
				const out = await model(id, ctl.signal);
				m = out.model;
				report = out.report;
				events = out.events;
				evidence = out.evidence ?? [];
				navSection.href = isApprovedList(out.model) ? '/approved' : '/pending';
			} catch (e) {
				if (e instanceof DOMException && e.name === 'AbortError') return;
				if (e instanceof Error && e.name === 'AbortError') return;
				error = e instanceof Error ? e.message : String(e);
			}
		})();
		return () => {
			ctl.abort();
			navSection.href = '';
		};
	});

	const reason = $derived(m ? reasonBeyondLabel(m) : '');
	const keyStep = $derived(m?.next.action === 'sign' || m?.next.action === 'accept');
</script>

<svelte:head><title>{m ? m.name : 'Model'} · Socair</title></svelte:head>

<h1 class="model-name">{m ? m.name : 'Model'}</h1>
{#if error}
	<div class="state failed" role="alert">
		<p class="error-title">This model could not be read</p>
		<p>{error}</p>
	</div>
{:else if m}
	<p class="meta">
		{m.location === 'clean' ? 'In the clean store' : 'In staging'} ·
		<span class="mono" title={m.id}>{m.id.slice(0, 12)}</span>{#if m.format}{' · '}{m.format}{/if}
	</p>

	<section class="status-block" aria-labelledby="status-h">
		<h2 id="status-h" class="visually-hidden">Status</h2>
		<p class="status-line">
			<span class="status tone-{stageTone(m)}">{stageLabel(m)}</span>
			{#if m.acceptance_expires}<span class="meta">until <When iso={m.acceptance_expires} rel /></span>{/if}
		</p>
		{#if reason}<p class="prose">{reason}</p>{/if}
		{#if m.issuer}
			<p class="meta">
				Issued by {m.issuer} · signed by key <span class="mono">{m.signer_key_id?.slice(0, 16)}</span>
			</p>
		{/if}
		{#if m.accepted_by}
			<p class="prose">Accepted by {m.accepted_by}{#if m.acceptance_expires}, until <When iso={m.acceptance_expires} />{/if}.</p>
			<p class="meta">{acceptedLine(m.accepted_surfaces)}</p>
			<ul class="surfaces">
				{#each m.accepted_surfaces ?? [] as s (s)}<li>{s}</li>{/each}
			</ul>
		{/if}
		{#if m.next.command}
			<h3>Next step</h3>
			{#if keyStep}<p class="meta">This step needs a key, so it runs in the CLI.</p>{/if}
			<Command command={m.next.command} purpose={nextPurpose(m.next.action)} />
		{/if}
	</section>

	{#if report}
		<ReportView {report} signed={!!m.signer_key_id} status={false} />
	{:else}
		<p class="meta">No verified report to show.</p>
	{/if}

	<section aria-labelledby="evidence-h">
		<h2 id="evidence-h">Evidence</h2>
		{#if evidence.length}
			<ul class="files">
				{#each evidence as f (f)}<li><a href={evidenceURL(m.id, f)} download>{f}</a></li>{/each}
			</ul>
		{:else}
			<p class="meta">This entry holds no evidence files yet.</p>
		{/if}
	</section>

	<section aria-labelledby="activity-h">
		<h2 id="activity-h">Activity</h2>
		{#if events.length}
			<EventList events={events.slice().reverse()} />
		{:else}
			<p class="meta">No log entries for this model.</p>
		{/if}
	</section>
{:else}
	<p class="meta" role="status">Reading the model.</p>
{/if}
