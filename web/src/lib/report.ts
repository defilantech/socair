// Display helpers over the engine's report document.
//
// These read the document. They never invent a status, a count, or a badge the
// engine did not return. NOT_TESTED is a deliberate non-signal and must never
// render with the pass treatment. LEAD is a suspicious signal that needs review,
// with its own treatment, never pass and never the neutral gap look.

import type { CheckStatus, Document, Measurement, MeasurementOutcome, NodeClass } from './api';

// Pill is the visual treatment for a status or a promotion state. 'conditions'
// is the amber caution of an authorization with conditions: never the pass
// look and never the neutral gap look. Conditions and needs-acceptance are
// amber. 'measured' is a Tier 2 measurement that found nothing: plain, never
// the pass look, because it is not evidence of absence.
export type Pill = 'pass' | 'fail' | 'lead' | 'not-tested' | 'conditions' | 'measured';

// statusPill maps a check status to its treatment. NOT_TESTED is never pass.
export function statusPill(status: CheckStatus): Pill {
	switch (status) {
		case 'PASS':
			return 'pass';
		case 'FAIL':
			return 'fail';
		case 'LEAD':
			return 'lead';
		default:
			return 'not-tested';
	}
}

// countOrder is the order ReportView shows the tally in: what needs action
// first, PASS last, so a conditional report does not open on its passes.
export const countOrder = ['fail', 'lead', 'notTested', 'pass'] as const;

export function counts(d: Document): {
	pass: number;
	fail: number;
	lead: number;
	notTested: number;
} {
	let pass = 0;
	let fail = 0;
	let lead = 0;
	let notTested = 0;
	for (const c of d.checks) {
		if (c.status === 'PASS') pass++;
		else if (c.status === 'FAIL') fail++;
		else if (c.status === 'LEAD') lead++;
		else notTested++;
	}
	return { pass, fail, lead, notTested };
}

// promotionLabel is the word for the promotion state, taken from the document.
export function promotionLabel(d: Document): string {
	switch (d.promotion_authorization.state) {
		case 'authorized':
			return 'authorized';
		case 'authorized_with_conditions':
			return 'authorized with conditions';
		case 'escalated':
			return 'escalated review';
		case 'withheld':
			return 'withheld';
		default:
			return d.promotion_authorization.state;
	}
}

// promotionPill gives the promotion state its treatment. Only a clean
// authorization reads as a pass; conditions read as an amber caution, never
// green and never the grey of a gap. Everything else (withheld, escalated)
// stays red: a withheld document is not cleared for the clean store.
export function promotionPill(d: Document): Pill {
	switch (d.promotion_authorization.state) {
		case 'authorized':
			return 'pass';
		case 'authorized_with_conditions':
			return 'conditions';
		default:
			return 'fail';
	}
}

// acceptedSurfaces lists what an acceptance covers. Only an authorization with
// conditions accepts anything, so every other state accepted nothing, whatever
// the document lists; its gaps are its NOT_TESTED rows.
export function acceptedSurfaces(d: Document): string[] {
	const pa = d.promotion_authorization;
	if (pa.state !== 'authorized_with_conditions') return [];
	return pa.accepted_surfaces ?? [];
}

// measurementPill maps a Tier 2 outcome to its treatment. A measurement is
// never a pass: one that found nothing is 'measured', and one that did not
// complete takes the gap look. A LEAD or FAIL measurement also has its check
// row, which is what the tally and the promotion state count.
export function measurementPill(outcome: MeasurementOutcome): Pill {
	switch (outcome) {
		case 'lead':
			return 'lead';
		case 'fail':
			return 'fail';
		case 'measured':
			return 'measured';
		default:
			return 'not-tested';
	}
}

// measurementSummary states a measurement's numbers as the engine sent them.
export function measurementSummary(m: Measurement): string {
	const parts: string[] = [];
	if (m.score !== undefined) {
		let s = `score ${m.score}`;
		if (m.ci95?.length === 2) s += ` (95% CI ${m.ci95[0]} to ${m.ci95[1]})`;
		parts.push(s);
	}
	parts.push(`n=${m.n}`);
	const metrics = m.metrics ?? {};
	for (const k of Object.keys(metrics).sort()) parts.push(`${k} ${metrics[k]}`);
	return parts.join(', ');
}

// nodeClassFacts lists a node class's reported fields and names the ones not
// reported, so a reader sees how complete the class is. An unreported switch
// is null (unknown), which is not the same as false.
export function nodeClassFacts(facts: NodeClass): { reported: string[]; unreported: string[] } {
	const reported: string[] = [];
	const unreported: string[] = [];
	for (const [k, v] of Object.entries(facts)) {
		if (k === 'schema') continue;
		let text = '';
		if (typeof v === 'boolean') text = String(v);
		else if (typeof v === 'number') text = v === 0 ? '' : String(v);
		else if (typeof v === 'string') text = v;
		else if (v && typeof v === 'object')
			text = Object.entries(v as Record<string, string>)
				.map(([ek, ev]) => `${ek}=${ev}`)
				.sort()
				.join(', ');
		if (text === '') unreported.push(k);
		else reported.push(`${k} ${text}`);
	}
	return { reported, unreported };
}

// shortHash abbreviates a "sha256:<hex>" digest for display.
export function shortHash(h: string): string {
	return h.startsWith('sha256:') && h.length > 19 ? h.slice(0, 19) : h;
}

export interface Level {
	id: string;
	label: string;
	available: boolean;
}

// availableLevels lists the assurance levels the wizard offers. Only Tier 1 is
// selectable. Tier 2 is configured on the engine (SOCAIR_TIER2_HELPER,
// docs/tier2.md), not chosen per scan, and has no checks of its own yet; a
// report from an engine where it ran shows its measurements.
export function availableLevels(): Level[] {
	return [
		{ id: 'tier1', label: 'Tier 1 (static)', available: true },
		{ id: 'tier2', label: 'Tier 2 (forward-pass probes)', available: false }
	];
}

// selectable is the one level the wizard may run.
export function selectable(): Level | undefined {
	return availableLevels().find((l) => l.available);
}
