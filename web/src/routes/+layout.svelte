<script lang="ts">
	import '../app.css';
	import favicon from '$lib/assets/favicon.svg';
	import { onMount } from 'svelte';
	import { page } from '$app/state';
	import { health, type Health } from '$lib/api';
	import { navSection } from '$lib/nav.svelte';
	import Cairn from '$lib/Cairn.svelte';

	let { children } = $props();
	let engine = $state<Health | null>(null);
	let engineError = $state('');
	const hasStore = $derived(engine?.store === 'ready');

	onMount(async () => {
		try {
			engine = await health();
		} catch (e) {
			engineError = e instanceof Error ? e.message : String(e);
		}
	});

	const links = [
		['/approved', 'Approved'],
		['/pending', 'Pending'],
		['/activity', 'Activity'],
		['/scan', 'Scan']
	] as const;

	// The current list: the page itself, or for a model page the list the
	// engine puts that model in.
	function current(href: string): boolean {
		return page.url.pathname.startsWith(href) || navSection.href === href;
	}
</script>

<svelte:head>
	<link rel="icon" href={favicon} type="image/svg+xml" />
</svelte:head>

<a class="skip" href="#main">Skip to content</a>
<header class="site-header">
	<div class="bar">
		<a class="home" href="/"><Cairn /></a>
		{#if hasStore}
			<nav class="console" aria-label="Console">
				<ul>
					{#each links as [href, label] (href)}
						<li><a {href} aria-current={current(href) ? 'page' : undefined}>{label}</a></li>
					{/each}
				</ul>
			</nav>
		{/if}
		<span class="engine">
			{#if engine}
				<span class="status tone-neutral solid" title="engine {engine.version}">engine ready</span>
			{:else if engineError}
				<span class="status tone-red" title={engineError}>engine unreachable</span>
			{:else}
				<span class="status tone-neutral">checking engine</span>
			{/if}
		</span>
	</div>
</header>

<main id="main" class="page" tabindex="-1">
	{@render children()}
</main>

<footer class="site-footer">
	<div class="bar">
		Socair is a Defilan Technologies product. This attestation does not certify the absence of unknown
		backdoors.
	</div>
</footer>
