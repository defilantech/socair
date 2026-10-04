<script lang="ts">
	import { onMount } from 'svelte';
	import { models, scanStaged, uploadAttestation, type Model } from '$lib/api';
	import { stageLabel, stageTone } from '$lib/console';

	let list = $state<Model[] | null>(null);
	let error = $state('');
	let busy = $state('');
	let errorTitle = $state('Something went wrong');

	async function load() {
		try {
			list = (await models()).filter((m) => m.location === 'staging');
			error = '';
		} catch (e) {
			list = null;
			error = e instanceof Error ? e.message : String(e);
		}
	}
	onMount(load);

	async function act(m: Model, title: string, f: () => Promise<unknown>) {
		busy = m.id;
		try {
			await f();
			await load();
		} catch (e) {
			const msg = e instanceof Error ? e.message : String(e);
			await load();
			errorTitle = title;
			error = msg;
		} finally {
			busy = '';
		}
	}

	async function onUpload(m: Model, ev: Event) {
		const input = ev.currentTarget as HTMLInputElement;
		const file = input.files?.[0];
		if (!file) return;
		const text = await file.text();
		input.value = '';
		await act(m, 'Upload refused', async () => uploadAttestation(m.id, text));
	}

	const order = ['ready', 'needs-acceptance', 'scanned', 'staged', 'blocked', 'acceptance-expired', 'does-not-verify'];
	const groups = $derived(
		list ? order.map((s) => [s, list!.filter((m) => m.stage === s)] as const).filter(([, ms]) => ms.length > 0) : []
	);
</script>

<div class="shell">
	<h2>Pending</h2>
	{#if error}<div class="state failed"><p class="error-title">{errorTitle}</p><p>{error}</p></div>{/if}
	{#if list === null && !error}<p class="hint">Reading the store.</p>{/if}
	{#if list && list.length === 0}<p>Nothing in staging. Pull a model with <code>socair airlock pull</code>, then scan it here.</p>{/if}
	{#each groups as [stage, ms] (stage)}
		<h3>{stage}</h3>
		{#each ms as m (m.id)}
			<div class="state">
				<p><a href="/models/{m.id}"><strong>{m.name}</strong></a> <span class="hint">{m.id.slice(0, 12)}</span> · <span class="tone-{stageTone(m)}">{stageLabel(m)}</span></p>
				{#if m.stage_reason}<p class="hint">{m.stage_reason}</p>{/if}
				{#if m.next.action === 'scan'}
					<button type="button" disabled={busy === m.id} onclick={() => act(m, 'Scan failed', () => scanStaged(m.id))}>{busy === m.id ? 'Scanning...' : 'Scan'}</button>
				{/if}
				{#if m.next.action === 'sign' || m.next.action === 'accept'}
					<p class="hint">This step needs a key, so it runs in the CLI:</p>
					<pre class="cmd">{m.next.command}</pre>
					<label>Or upload the signed result <input type="file" accept=".json" onchange={(ev) => onUpload(m, ev)} /></label>
				{/if}
				{#if m.next.action === 'promote'}
					<pre class="cmd">{m.next.command}</pre>
				{/if}
			</div>
		{/each}
	{/each}
</div>
