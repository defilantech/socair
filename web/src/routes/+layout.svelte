<script lang="ts">
	import '../app.css';
	import favicon from '$lib/assets/favicon.svg';
	import { onMount } from 'svelte';
	import { page } from '$app/state';
	import { health } from '$lib/api';

	let { children } = $props();
	let hasStore = $state(false);

	onMount(async () => {
		try {
			hasStore = (await health()).store === 'ready';
		} catch {
			hasStore = false;
		}
	});

	const links = [
		['/approved', 'Approved'],
		['/pending', 'Pending'],
		['/activity', 'Activity'],
		['/scan', 'Scan']
	];
</script>

<svelte:head>
	<link rel="icon" href={favicon} />
	<title>Socair: model assurance</title>
</svelte:head>

{#if hasStore}
	<nav class="console" aria-label="Console">
		{#each links as [href, label] (href)}
			<a {href} aria-current={page.url.pathname.startsWith(href) ? 'page' : undefined}>{label}</a>
		{/each}
	</nav>
{/if}

{@render children()}
