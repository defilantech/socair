<script lang="ts">
	import type { Document } from '$lib/api';
	import { statusPill, promotionLabel, promotionPill, counts } from '$lib/report';

	let { report, signed = false }: { report: Document; signed?: boolean } = $props();
	const c = $derived(counts(report));
</script>

	<p>
		<span class="pill {promotionPill(report)}">{promotionLabel(report)}</span>
		&nbsp; Tier 1 (static) &middot; {signed ? 'signed' : 'unsigned until signed (socair sign)'}
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
		<strong>{report.artifact.name}</strong> &middot; {report.artifact.format} &middot;
		{report.artifact.file_name}
	</p>
	<p class="hint" style="overflow-wrap:anywhere">SHA-256 {report.artifact.sha256}</p>

	<h2>Checks performed</h2>
	<table>
		<thead>
			<tr><th>Check</th><th>Looks for</th><th>Result</th><th>Notes</th></tr>
		</thead>
		<tbody>
			{#each report.checks as check (check.name)}
				<tr>
					<td class="check">{check.name}</td>
					<td class="evidence">
						{check.looks_for}
						{#if check.pass_means}<div class="pass-means"><strong>PASS means:</strong> {check.pass_means}</div>{/if}
						{#if check.maps_to?.length}<div class="maps">Addresses {check.maps_to.map((m) => m.id).join(' · ')}</div>{/if}
					</td>
					<td>
						<span class="pill {statusPill(check.status)}">{check.status}</span>
						{#if check.severity}<span class="severity">{check.severity}</span>{/if}
					</td>
					<td class="notes">{check.notes ?? ''}</td>
				</tr>
			{/each}
		</tbody>
	</table>

	<p class="bounded">{report.bounded_statement}</p>

	<div class="ceiling">
		<p>{report.out_of_scope.does_not_certify}</p>
		<ul>
			{#each report.out_of_scope.ceiling as item (item)}
				<li>{item}</li>
			{/each}
		</ul>
	</div>

	{#if report.promotion_authorization.conditions}
		<p class="hint">{report.promotion_authorization.conditions}</p>
	{/if}
