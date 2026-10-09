<script lang="ts">
	import type { Document } from '$lib/api';
	import { statusPill, promotionLabel, promotionPill, counts, countOrder } from '$lib/report';

	// The engine's report, read-only. Section numbers follow the attestation
	// template (docs/attestation-template.md), and the bounded statement's
	// closing reference, "Out of scope", is section 8's heading here. `status`
	// shows the document's promotion state; a page with its own status block
	// (a model page) passes false so one state, and its accepted gaps, are not
	// shown twice.
	let {
		report,
		signed = false,
		status = true
	}: { report: Document; signed?: boolean; status?: boolean } = $props();

	const c = $derived(counts(report));
	const countLabel = { fail: 'FAIL', lead: 'LEAD', notTested: 'NOT TESTED', pass: 'PASS' } as const;
	const countPill = { fail: 'fail', lead: 'lead', notTested: 'not-tested', pass: 'pass' } as const;
	const pa = $derived(report.promotion_authorization);
</script>

<div class="report">
	{#if status}
		<p class="report-status">
			<span class="pill {promotionPill(report)}">{promotionLabel(report)}</span>
			<span class="meta">Tier 1 (static) · {signed ? 'signed' : 'unsigned until signed (socair sign)'}</span>
		</p>
	{:else}
		<p class="meta">Tier 1 (static) · {signed ? 'signed' : 'unsigned until signed (socair sign)'}</p>
	{/if}

	<ul class="tally" aria-label="Check results">
		{#each countOrder as k (k)}
			<li><b>{c[k]}</b> <span class="pill {countPill[k]}">{countLabel[k]}</span></li>
		{/each}
	</ul>

	<section aria-labelledby="sec-2">
		<h2 id="sec-2">2. Artifact identity</h2>
		<dl class="facts">
			{#if report.artifact.name !== report.artifact.file_name}<dt>Name</dt><dd>{report.artifact.name}</dd>{/if}
			<dt>File</dt><dd>{report.artifact.file_name}</dd>
			<dt>Format</dt><dd>{report.artifact.format}</dd>
			<dt>SHA-256</dt><dd class="hash">{report.artifact.sha256}</dd>
		</dl>
	</section>

	{#if report.scope}
		<section aria-labelledby="sec-3">
			<h2 id="sec-3">3. Scope and method</h2>
			<dl class="facts">
				<dt>Execution context</dt><dd>{report.scope.execution_context}</dd>
				<dt>Check set</dt><dd>{report.scope.check_set_version}</dd>
				{#if report.scope.reference_data}<dt>Reference data</dt><dd>{report.scope.reference_data}</dd>{/if}
			</dl>
		</section>
	{/if}

	<section aria-labelledby="sec-4">
		<h2 id="sec-4">4. Checks performed</h2>
		<table class="stack checks">
			<thead>
				<tr><th scope="col">Check</th><th scope="col">Looks for</th><th scope="col">Result</th><th scope="col">Notes</th></tr>
			</thead>
			<tbody>
				{#each report.checks as check (check.name)}
					<tr>
						<th scope="row" class="check" data-label="Check">{check.name}</th>
						<td class="evidence" data-label="Looks for">
							{check.looks_for}
							{#if check.pass_means}<div class="pass-means">
									<strong>{check.status === 'PASS' ? 'PASS means:' : 'A pass would mean:'}</strong>
									{check.pass_means}
								</div>{/if}
							{#if check.maps_to?.length}<div class="maps">Addresses {check.maps_to.map((m) => m.id).join(' · ')}</div>{/if}
						</td>
						<td data-label="Result">
							<span class="pill {statusPill(check.status)}">{check.status}</span>
							{#if check.severity}<span class="severity">{check.severity}</span>{/if}
						</td>
						<td class="notes" data-label="Notes">{check.notes ?? ''}</td>
					</tr>
				{/each}
			</tbody>
		</table>
	</section>

	<section aria-labelledby="sec-7">
		<h2 id="sec-7">7. Bounded statement</h2>
		<p class="bounded">{report.bounded_statement}</p>
	</section>

	<section class="ceiling" aria-labelledby="sec-8">
		<h2 id="sec-8">8. Out of scope and not tested</h2>
		<p class="ceiling-head">{report.out_of_scope.does_not_certify}</p>
		<ul>
			{#each report.out_of_scope.ceiling as item (item)}
				<li>{item}</li>
			{/each}
		</ul>
		{#if report.out_of_scope.not_run?.length}
			<h3>Checks not run at this level</h3>
			<ul>
				{#each report.out_of_scope.not_run as n (n.name)}
					<li><strong>{n.name}</strong> ({n.looks_for}): {n.reason}</li>
				{/each}
			</ul>
		{/if}
		{#if report.out_of_scope.untested_node_classes?.length}
			<h3>Node classes not tested</h3>
			<ul>
				{#each report.out_of_scope.untested_node_classes as n (n)}<li>{n}</li>{/each}
			</ul>
		{/if}
	</section>

	{#if pa.conditions || (status && pa.accepted_surfaces?.length)}
		<section aria-labelledby="sec-9">
			<h2 id="sec-9">9. Promotion authorization</h2>
			{#if pa.conditions}<p class="prose">{pa.conditions}</p>{/if}
			{#if status && pa.accepted_surfaces?.length}
				<p class="meta">Accepted, not tested{pa.accepted_by ? `, by ${pa.accepted_by}` : ''}:</p>
				<ul class="surfaces">
					{#each pa.accepted_surfaces as s (s)}<li>{s}</li>{/each}
				</ul>
			{/if}
		</section>
	{/if}
</div>
