<script lang="ts">
	import { onMount } from 'svelte';
	import { models, exportSnapshot, type Model } from '$lib/api';
	import { stageLabel, stageTone, isApprovedList } from '$lib/console';

	let list = $state<Model[] | null>(null);
	let error = $state('');
	let exporting = $state(false);
	let exportError = $state('');

	onMount(async () => {
		try {
			list = (await models()).filter(isApprovedList);
		} catch (e) {
			list = null;
			error = e instanceof Error ? e.message : String(e);
		}
	});

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

<div class="shell">
	<h2>Approved models</h2>
	{#if error}
		<div class="state failed"><p class="error-title">The store could not be read</p><p>{error}</p></div>
	{:else if list === null}
		<p class="hint">Reading the store.</p>
	{:else if list.length === 0}
		<p>No approved models. Pull one into staging with <code>socair airlock pull</code>, then scan, sign, and promote it from <a href="/pending">Pending</a>.</p>
	{:else}
		<table>
			<thead><tr><th>Model</th><th>State</th><th>Issuer</th><th>Accepted gaps</th><th>Promoted</th></tr></thead>
			<tbody>
				{#each list as m (m.id)}
					<tr>
						<td class="check"><a href="/models/{m.id}">{m.name}</a><div class="hint">{m.id.slice(0, 12)} · {m.format ?? ''}</div></td>
						<td><span class="tone-{stageTone(m)}">{stageLabel(m)}</span>{#if m.stage_reason}<div class="hint">{m.stage_reason}</div>{/if}</td>
						<td>{m.issuer ?? ''}</td>
						<td>{(m.accepted_surfaces ?? []).join(', ')}</td>
						<td>{m.promoted_at ?? ''}</td>
					</tr>
				{/each}
			</tbody>
		</table>
	{/if}

	<h2>Share a snapshot</h2>
	<p class="hint">
		An unsigned snapshot for a quick look. For leadership or an auditor, export a signed one with the operator key (STORE is this store's path):
	</p>
	<pre class="cmd">socair airlock export --store STORE --out snapshot --key OPERATOR_KEY</pre>
	<div class="actions"><button type="button" onclick={onExport} disabled={exporting}>{exporting ? 'Exporting...' : 'Download unsigned snapshot'}</button></div>
	{#if exportError}<div class="state failed"><p class="error-title">The snapshot could not be exported</p><p>{exportError}</p></div>{/if}
</div>
