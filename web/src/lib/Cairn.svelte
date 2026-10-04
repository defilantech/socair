<script lang="ts">
	// The Socair mark: the cairn's three stones and the wordmark. The paths are
	// the canonical ones from socair-web (src/routes/+page.svelte); never
	// redraw them. The top stone is sea-green, the lower two mist.
	const stones = [
		{
			d: 'M10 52 C 9 45.5, 17 41.5, 31 41.5 C 46 41.5, 55 44.5, 55 51 C 55 57, 45 59.5, 31 59.5 C 18 59.5, 10.5 57.5, 10 52 Z',
			transform: ''
		},
		{
			d: 'M15 34.5 C 15 30, 22 27.5, 31 27.5 C 40.5 27.5, 47.5 29.5, 47.5 33.8 C 47.5 37.8, 40.5 39.5, 31 39.5 C 21.5 39.5, 15 38.3, 15 34.5 Z',
			transform: 'rotate(3 31 33.5)'
		},
		{
			d: 'M25 21.2 C 25 17.6, 30.5 15.6, 36.5 15.6 C 42.5 15.6, 46.5 17.4, 46.5 20.6 C 46.5 23.6, 42 25, 36 25 C 29.8 25, 25 24.2, 25 21.2 Z',
			transform: 'rotate(-7 36 20.3)'
		}
	];
</script>

<svg class="cairn" viewBox="0 0 330 80" role="img" aria-label="Socair">
	<g transform="translate(4,8)">
		{#each stones as s, i (i)}
			<path d={s.d} transform={s.transform} fill={i === 2 ? '#4CD3AE' : '#E7EEF1'} />
		{/each}
	</g>
	<g
		transform="translate(92,26)"
		fill="none"
		stroke="#E7EEF1"
		stroke-width="7"
		stroke-linecap="round"
		stroke-linejoin="round"
	>
		<path d="M27 8 C 22 2, 6 2, 6 12 C 6 22, 28 18, 28 29 C 28 40, 9 40, 4 33" />
		<circle cx="55" cy="20.5" r="17.5" />
		<path d="M117 8 A 17.5 17.5 0 1 0 117 33" />
		<circle cx="145" cy="20.5" r="17.5" />
		<path d="M162.5 4 L 162.5 37.5" />
		<path d="M182 4 L 182 37.5" />
		<circle cx="182" cy="-11" r="4.5" fill="#E7EEF1" stroke="none" />
		<path d="M200 37.5 L 200 4" />
		<path d="M200 18 C 200 8, 208 3, 220 4" />
	</g>
</svg>
