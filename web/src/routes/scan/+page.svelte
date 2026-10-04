<script lang="ts">
	import { onMount } from 'svelte';
	import {
		scan,
		downloadReport,
		health,
		airlockLog,
		type AirlockEvent,
		type Health
	} from '$lib/api';
	import { runScan, canDownload, type RunState } from '$lib/run';
	import { availableLevels, selectable } from '$lib/report';
	import ReportView from '$lib/ReportView.svelte';

	let path = $state('');
	let levelId = $state(selectable()?.id ?? '');
	let run = $state<RunState>({ kind: 'idle' });
	let busy = $state(false);

	let engine = $state<Health | null>(null);
	let engineError = $state('');
	let events = $state<AirlockEvent[]>([]);

	const levels = availableLevels();

	onMount(async () => {
		try {
			engine = await health();
		} catch (e) {
			engineError = e instanceof Error ? e.message : String(e);
		}
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

<div class="shell">
	<header class="masthead">
		<h1 class="wordmark">Socair<span>model assurance</span></h1>
		{#if engine}
			<span class="chip ok" title="engine {engine.version}">engine ready</span>
		{:else if engineError}
			<span class="chip bad" title={engineError}>engine unreachable</span>
		{:else}
			<span class="chip">checking engine</span>
		{/if}
	</header>

	<h2>Scan an artifact</h2>
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
			/>
			<p class="hint">A GGUF on this host, or a path an airlock ingest resolved.</p>
		</div>
		<div class="row">
			<div>
				<label for="level">Assurance level</label>
				<select id="level" bind:value={levelId}>
					{#each levels as l (l.id)}
						<option value={l.id} disabled={!l.available}>{l.label}</option>
					{/each}
				</select>
				<p class="hint">Tier 2 is the paid forward-pass tier and has no checks yet.</p>
			</div>
			<div>
				<div class="spacer" aria-hidden="true"></div>
				<button type="submit" disabled={busy}>{busy ? 'Scanning...' : 'Run the scan'}</button>
			</div>
		</div>
	</form>

	<div class="result" aria-live="polite">
		{#if run.kind === 'idle'}
			<div class="state">
				<p>Point at an artifact and run the scan. The report it produces is the one you file.</p>
			</div>
		{:else if run.kind === 'running'}
			<div class="state"><p>Scanning. Hashing the artifact and running the Tier 1 checks.</p></div>
		{:else if run.kind === 'failed'}
			<div class="state failed">
				<p class="error-title">The scan did not complete</p>
				<p>{run.error}</p>
				<p class="hint">No report was produced, so nothing is offered for download.</p>
			</div>
		{:else}
			<div class="state">
				<ReportView report={run.report} />

				<h2>Take the report</h2>
				<div class="actions">
					<button type="button" onclick={() => download('html')} disabled={!canDownload(run)}
						>Download HTML</button
					>
					<button
						type="button"
						class="ghost"
						onclick={() => download('pdf')}
						disabled={!canDownload(run)}>Download PDF</button
					>
				</div>
			</div>
		{/if}
	</div>

	{#if events.length > 0}
		<h2>Airlock activity</h2>
		<ul class="ledger">
			{#each events.slice(-8).reverse() as e, i (i)}
				<li>{e.ts} &middot; {e.action} &middot; {e.outcome}{e.detail ? `: ${e.detail}` : ''}</li>
			{/each}
		</ul>
	{/if}

	<footer class="foot">
		Socair is a Defilan Technologies product. This attestation does not certify the
		absence of unknown backdoors.
	</footer>
</div>
