<script lang="ts">
	import { onMount } from 'svelte';
	import { goto } from '$app/navigation';
	import { health } from '$lib/api';

	// With a store, the console's home is the approved list; without one, the
	// scan page, as before.
	onMount(async () => {
		try {
			const h = await health();
			await goto(h.store === 'ready' ? '/approved' : '/scan', { replaceState: true });
		} catch {
			await goto('/scan', { replaceState: true });
		}
	});
</script>

<svelte:head><title>Socair</title></svelte:head>

<h1 class="visually-hidden">Socair</h1>
<p class="meta" role="status">Opening the console.</p>
