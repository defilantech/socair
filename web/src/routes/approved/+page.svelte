<script lang="ts">
	import { onMount } from 'svelte';
	import { models, exportSnapshot, type Model } from '$lib/api';
	import { stageLabel, stageTone, approvedSections, reasonBeyondLabel, acceptedLine } from '$lib/console';
	import Command from '$lib/Command.svelte';
	import When from '$lib/When.svelte';

	let list = $state<Model[] | null>(null);
	let error = $state('');
	let exporting = $state(false);
	let exportError = $state('');

	onMount(async () => {
		try {
			list = await models();
		} catch (e) {
			list = null;
			error = e instanceof Error ? e.message : String(e);
		}
	});

	const sections = $derived(list ? approvedSections(list) : []);

	async function onExport() {
		exporting = true;
		exportError = '';
		try {
			const blob = await exportSnapshot();
			const a = document.createElement('a');
			a.href = URL.createObjectURL(blob);
			a.download = 'socair-inventory.zip';
			a.click();
			const href = a.href;
			setTimeout(() => URL.revokeObjectURL(href), 1000);
		} catch (e) {
			exportError = e instanceof Error ? e.message : String(e);
		} finally {
			exporting = false;
		}
	}
</script>

<svelte:head><title>In the clean store · Socair</title></svelte:head>

<h1>In the clean store</h1>
<p class="lede">Everything the airlock has promoted, including approvals with conditions and entries that are no longer valid.</p>

{#if error}
	<div class="state failed" role="alert"><p class="error-title">The store could not be read</p><p>{error}</p></div>
{:else if list === null}
	<p class="meta" role="status">Reading the store.</p>
{:else if sections.length === 0}
	<p class="prose">
		Nothing has been promoted yet. Pull a model into staging with <code>socair airlock pull</code>, then scan,
		sign, and promote it from <a href="/pending">Pending</a>.
	</p>
{:else}
	{#each sections as sec (sec.key)}
		<section aria-labelledby="sec-{sec.key}">
			<h2 id="sec-{sec.key}">{sec.heading}</h2>
			<table class="stack models">
				<thead>
					<tr>
						<th scope="col">Model</th>
						<th scope="col">Status</th>
						{#if sec.key === 'conditions'}
							<th scope="col">Accepted gaps</th>
							<th scope="col">Acceptance expires</th>
						{/if}
						<th scope="col">Issuer</th>
						<th scope="col">Promoted</th>
					</tr>
				</thead>
				<tbody>
					{#each sec.models as m (m.id)}
						{@const reason = reasonBeyondLabel(m)}
						<tr>
							<th scope="row" class="check" data-label="Model">
								<a href="/models/{m.id}">{m.name}</a>
								<div class="meta"><span class="mono">{m.id.slice(0, 12)}</span>{#if m.format} · {m.format}{/if}</div>
							</th>
							<td data-label="Status">
								<span class="status tone-{stageTone(m)}">{stageLabel(m)}</span>
								{#if reason}<div class="meta">{reason}</div>{/if}
							</td>
							{#if sec.key === 'conditions'}
								<td data-label="Accepted gaps">
									<div class="meta">{acceptedLine(m.accepted_surfaces)}</div>
									<ul class="surfaces">
										{#each m.accepted_surfaces ?? [] as s (s)}<li>{s}</li>{/each}
									</ul>
								</td>
								<td data-label="Acceptance expires"><When iso={m.acceptance_expires} rel /></td>
							{/if}
							<td data-label="Issuer">{m.issuer ?? ''}</td>
							<td data-label="Promoted"><When iso={m.promoted_at} /></td>
						</tr>
					{/each}
				</tbody>
			</table>
		</section>
	{/each}
{/if}

<section aria-labelledby="snapshot-h">
	<h2 id="snapshot-h">Share a snapshot</h2>
	<p class="prose">
		For leadership or an auditor, export a signed snapshot with the operator key. STORE is this store's path.
	</p>
	<Command
		command="socair airlock export --store STORE --out snapshot --key OPERATOR_KEY"
		purpose="Exports a signed inventory snapshot with your operator key"
	/>
	<p class="prose">Or download an unsigned snapshot for a quick look:</p>
	<div class="actions">
		<button type="button" class="secondary" onclick={onExport} disabled={exporting}
			>{exporting ? 'Exporting...' : 'Download unsigned snapshot'}</button
		>
	</div>
	{#if exportError}<div class="state failed" role="alert">
			<p class="error-title">The snapshot could not be exported</p>
			<p>{exportError}</p>
		</div>{/if}
</section>
