<script lang="ts">
	import { onMount } from 'svelte';
	import { models, scanStaged, uploadAttestation, type Model } from '$lib/api';
	import { stageLabel, stageTone, pendingHeading, reasonBeyondLabel, nextPurpose } from '$lib/console';
	import Command from '$lib/Command.svelte';

	let list = $state<Model[] | null>(null);
	let error = $state('');
	let busy = $state('');
	let errorTitle = $state('Something went wrong');
	let announcement = $state('');

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

	// act runs one console action, reloads the list, and announces where the
	// model went using the state the engine returned for it.
	async function act(m: Model, title: string, verb: string, f: () => Promise<Model>) {
		busy = m.id;
		announcement = '';
		try {
			const after = await f();
			await load();
			announcement = `${verb}: ${after.name} is now ${stageLabel(after)}`;
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
		await act(m, 'Upload refused', 'Uploaded', () => uploadAttestation(m.id, text));
	}

	const order = ['ready', 'needs-acceptance', 'scanned', 'staged', 'blocked', 'acceptance-expired', 'does-not-verify'];
	const groups = $derived(
		list ? order.map((s) => [s, list!.filter((m) => m.stage === s)] as const).filter(([, ms]) => ms.length > 0) : []
	);
</script>

<svelte:head><title>Pending · Socair</title></svelte:head>

<h1>Pending</h1>
<p class="lede">Models in staging, grouped by what each one waits for. Steps that need a key run in the CLI.</p>

<p class="announce" role="status" aria-live="polite">{announcement}</p>
{#if error}<div class="state failed" role="alert"><p class="error-title">{errorTitle}</p><p>{error}</p></div>{/if}
{#if list === null && !error}<p class="meta" role="status">Reading the store.</p>{/if}
{#if list && list.length === 0}
	<p class="prose">Nothing in staging. Pull a model with <code>socair airlock pull</code>, then scan it here.</p>
{/if}

{#each groups as [stage, ms] (stage)}
	<section aria-labelledby="g-{stage}">
		<h2 id="g-{stage}">{pendingHeading(stage)}</h2>
		<ul class="rows">
			{#each ms as m (m.id)}
				{@const reason = reasonBeyondLabel(m)}
				<li class="row-item">
					<div class="row-head">
						<h3><a href="/models/{m.id}">{m.name}</a></h3>
						<span class="mono meta">{m.id.slice(0, 12)}</span>
						<span class="status tone-{stageTone(m)}">{stageLabel(m)}</span>
					</div>
					{#if reason}<p class="meta">{reason}</p>{/if}
					{#if m.next.action === 'scan'}
						<div class="actions">
							<button
								type="button"
								disabled={busy === m.id}
								onclick={() => act(m, 'Scan failed', 'Scanned', () => scanStaged(m.id))}
								>{busy === m.id ? 'Scanning...' : 'Scan'}</button
							>
						</div>
					{/if}
					{#if (m.next.action === 'sign' || m.next.action === 'accept') && m.next.command}
						<p class="meta">This step needs a key, so it runs in the CLI. Then upload the signed result here.</p>
						<Command command={m.next.command} purpose={nextPurpose(m.next.action)} />
						<div class="actions">
							<label class="file-button" class:busy={busy === m.id}>
								<input
									class="visually-hidden"
									type="file"
									accept=".json"
									disabled={busy === m.id}
									onchange={(ev) => onUpload(m, ev)}
								/>
								<span>{busy === m.id ? 'Uploading...' : 'Upload signed attestation'}</span>
								<span class="file-hint">(report.dsse.json or report.conditional.dsse.json)</span>
							</label>
						</div>
					{/if}
					{#if m.next.action === 'promote' && m.next.command}
						<Command command={m.next.command} purpose={nextPurpose(m.next.action)} />
					{/if}
				</li>
			{/each}
		</ul>
	</section>
{/each}
