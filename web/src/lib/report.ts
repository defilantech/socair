// Display helpers over the engine's report document.
//
// These read the document. They never invent a status, a count, or a badge the
// engine did not return. NOT_TESTED is a deliberate non-signal and must never
// render with the pass treatment. LEAD is a suspicious signal for escalation
// with its own treatment, never pass and never the neutral gap look.

import type { CheckStatus, Document } from './api';

// Pill is the visual treatment for a status or a promotion state. 'conditions'
// is the amber caution of an authorization with conditions: never the pass
// look and never the neutral gap look (PRODUCT.md, Capabilities and
// Constraints: conditions and needs-acceptance are amber).
export type Pill = 'pass' | 'fail' | 'lead' | 'not-tested' | 'conditions';

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

export interface Level {
	id: string;
	label: string;
	available: boolean;
}

// availableLevels lists the assurance levels the wizard offers. Only Tier 1 is
// runnable today; Tier 2 is the paid forward-pass tier and has no checks, so it
// must not be selectable.
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
