<script lang="ts">
	import { onMount } from 'svelte';
	import { scan, downloadReport, airlockLog, type AirlockEvent } from '$lib/api';
	import { runScan, canDownload, type RunState } from '$lib/run';
	import { availableLevels, selectable } from '$lib/report';
	import ReportView from '$lib/ReportView.svelte';
	import EventList from '$lib/EventList.svelte';

	let path = $state('');
	let levelId = $state(selectable()?.id ?? '');
	let run = $state<RunState>({ kind: 'idle' });
	let busy = $state(false);

	let events = $state<AirlockEvent[]>([]);

	const levels = availableLevels();

	onMount(async () => {
		try {
			events = await airlockLog();
		} catch {
			// The airlock may be absent on an API-only run; the wizard does not
			// invent state for it.
		}
	});

	async function onSubmit(ev: SubmitEvent) {
		ev.preventDefault();
		busy = true;
		run = { kind: 'running' };
		run = await runScan(scan, path);
		busy = false;
	}

	async function download(format: 'html' | 'pdf') {
		if (run.kind !== 'done') return;
		const short = run.report.artifact.sha256.slice(0, 12);
		await downloadReport(run.report, format, `socair-attestation-${short}.${format}`);
	}
</script>

<svelte:head><title>Scan an artifact · Socair</title></svelte:head>

<h1>Scan an artifact</h1>
<p class="lede">Point at a model on this host and run the Tier 1 checks. The report it produces is the one you file.</p>

<form class="scan" onsubmit={onSubmit}>
	<div>
		<label for="artifact-path">Artifact path</label>
		<input
			id="artifact-path"
			type="text"
			bind:value={path}
			placeholder="/models/model.gguf"
			autocomplete="off"
			spellcheck="false"
			aria-describedby="artifact-hint"
		/>
		<p class="hint" id="artifact-hint">A GGUF on this host, or a path an airlock ingest resolved.</p>
	</div>
	<div class="row">
		<div>
			<label for="level">Assurance level</label>
			<select id="level" bind:value={levelId} aria-describedby="level-hint">
				{#each levels as l (l.id)}
					<option value={l.id} disabled={!l.available}>{l.label}</option>
				{/each}
			</select>
			<p class="hint" id="level-hint">Tier 2 is the paid forward-pass tier and has no checks yet.</p>
		</div>
		<div class="row-action">
			<button type="submit" disabled={busy}>{busy ? 'Scanning...' : 'Run the scan'}</button>
		</div>
	</div>
</form>

<div class="result" aria-live="polite">
	{#if run.kind === 'idle'}
		<p class="meta">No scan yet.</p>
	{:else if run.kind === 'running'}
		<p class="meta" role="status">Scanning. Hashing the artifact and running the Tier 1 checks.</p>
	{:else if run.kind === 'failed'}
		<div class="state failed">
			<p class="error-title">The scan did not complete</p>
			<p>{run.error}</p>
			<p class="hint">No report was produced, so nothing is offered for download.</p>
		</div>
	{:else}
		<ReportView report={run.report} />

		<h2>Take the report</h2>
		<div class="actions">
			<button type="button" onclick={() => download('html')} disabled={!canDownload(run)}>Download HTML</button>
			<button type="button" class="secondary" onclick={() => download('pdf')} disabled={!canDownload(run)}
				>Download PDF</button
			>
		</div>
	{/if}
</div>

{#if events.length > 0}
	<section aria-labelledby="airlock-h">
		<h2 id="airlock-h">Airlock activity</h2>
		<EventList events={events.slice(-8).reverse()} />
	</section>
{/if}
