<script lang="ts">
	import { shortDate, relative } from './when';

	// A date as the engine stated it: the full ISO value stays in datetime and
	// title; the visible text is short. `rel` adds "in 18 days" for expiries.
	let { iso, rel = false }: { iso: string | undefined; rel?: boolean } = $props();
	const distance = $derived(rel ? relative(iso) : '');
</script>

{#if iso}<time datetime={iso} title={iso}>{shortDate(iso)}</time>{#if distance}<span class="rel"> ({distance})</span>{/if}{/if}
