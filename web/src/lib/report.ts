// Display helpers over the engine's report document.
//
// These read the document. They never invent a status, a count, or a badge the
// engine did not return. NOT_TESTED is a deliberate non-signal and must never
// render with the pass treatment. LEAD is a suspicious signal for escalation
// with its own treatment, never pass and never the neutral gap look.

import type { CheckStatus, Document } from './api';

// Pill is the visual treatment for a status or a promotion state.
export type Pill = 'pass' | 'fail' | 'lead' | 'not-tested';

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
// authorization reads as a pass; conditions read as a caution, never green.
export function promotionPill(d: Document): Pill {
	switch (d.promotion_authorization.state) {
		case 'authorized':
			return 'pass';
		case 'authorized_with_conditions':
			return 'not-tested';
		default:
			return 'fail';
	}
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
