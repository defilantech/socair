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
	import {
		statusPill,
		promotionLabel,
		promotionPill,
		counts,
		availableLevels,
		selectable
	} from '$lib/report';

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

	const c = $derived(run.kind === 'done' ? counts(run.report) : null);
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
			{@const d = run.report}
			<div class="state">
				<p>
					<span class="pill {promotionPill(d)}">{promotionLabel(d)}</span>
					&nbsp; Tier 1 (static) &middot; unsigned (OSS tier)
				</p>
				{#if c}
					<div class="counts">
						<span class="count"><b>{c.pass}</b><span>pass</span></span>
						<span class="count"><b>{c.fail}</b><span>fail</span></span>
						<span class="count"><b>{c.lead}</b><span>lead</span></span>
						<span class="count"><b>{c.notTested}</b><span>not tested</span></span>
					</div>
				{/if}

				<p>
					<strong>{d.artifact.name}</strong> &middot; {d.artifact.format} &middot;
					{d.artifact.file_name}
				</p>
				<p class="hint" style="overflow-wrap:anywhere">SHA-256 {d.artifact.sha256}</p>

				<h2>Checks performed</h2>
				<table>
					<thead>
						<tr><th>Check</th><th>Looks for</th><th>Result</th><th>Notes</th></tr>
					</thead>
					<tbody>
						{#each d.checks as check (check.name)}
							<tr>
								<td class="check">{check.name}</td>
								<td class="evidence">
									{check.looks_for}
									{#if check.pass_means}<div class="pass-means"><strong>PASS means:</strong> {check.pass_means}</div>{/if}
								</td>
								<td><span class="pill {statusPill(check.status)}">{check.status}</span></td>
								<td class="notes">{check.notes ?? ''}</td>
							</tr>
						{/each}
					</tbody>
				</table>

				<p class="bounded">{d.bounded_statement}</p>

				<div class="ceiling">
					<p>{d.out_of_scope.does_not_certify}</p>
					<ul>
						{#each d.out_of_scope.ceiling as item (item)}
							<li>{item}</li>
						{/each}
					</ul>
				</div>

				{#if d.promotion_authorization.conditions}
					<p class="hint">{d.promotion_authorization.conditions}</p>
				{/if}

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
			{#each events.slice(-8).reverse() as e (e.ts + e.action)}
				<li>{e.ts} &middot; {e.action} &middot; {e.outcome}{e.detail ? `: ${e.detail}` : ''}</li>
			{/each}
		</ul>
	{/if}

	<footer class="foot">
		Socair is a Defilan Technologies product. This attestation does not certify the
		absence of unknown backdoors.
	</footer>
</div>
