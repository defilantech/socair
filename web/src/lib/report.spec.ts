import { describe, it, expect } from 'vitest';
import type { Document } from './api';
import {
	statusPill,
	promotionLabel,
	promotionPill,
	acceptedSurfaces,
	counts,
	countOrder,
	availableLevels
} from './report';

function doc(state: string, statuses: string[]): Document {
	return {
		schema_version: 'socair.report/v1',
		artifact: {
			name: 'm',
			file_name: 'm.gguf',
			sha256: 'a'.repeat(64),
			format: 'GGUF',
			size_bytes: 1
		},
		checks: statuses.map((s, i) => ({ name: `c${i}`, looks_for: 'x', status: s as never })),
		findings: { fails: [], not_tested: [] },
		promotion_authorization: { authorized: state === 'authorized', state },
		bounded_statement: 'x',
		out_of_scope: { does_not_certify: 'x', ceiling: ['x'] },
		verification: { artifact_sha256: 'a'.repeat(64) }
	};
}

describe('status treatment', () => {
	it('never renders NOT_TESTED as a pass', () => {
		expect(statusPill('NOT_TESTED')).toBe('not-tested');
		expect(statusPill('NOT_TESTED')).not.toBe('pass');
	});
	it('maps PASS and FAIL distinctly', () => {
		expect(statusPill('PASS')).toBe('pass');
		expect(statusPill('FAIL')).toBe('fail');
	});
	it('gives LEAD its own treatment, never pass or the gap look', () => {
		expect(statusPill('LEAD')).toBe('lead');
		expect(statusPill('LEAD')).not.toBe('pass');
		expect(statusPill('LEAD')).not.toBe('not-tested');
	});
});

describe('promotion badge', () => {
	it('comes from the document, not a constant', () => {
		expect(promotionLabel(doc('authorized', []))).toBe('authorized');
		expect(promotionLabel(doc('withheld', []))).toBe('withheld');
	});
	it('never shows a withheld document as authorized', () => {
		expect(promotionPill(doc('withheld', []))).toBe('fail');
		expect(promotionLabel(doc('withheld', []))).not.toBe('authorized');
	});
	it('treats conditions as a caution, never clean green', () => {
		expect(promotionPill(doc('authorized_with_conditions', []))).not.toBe('pass');
	});
	// PRODUCT.md (Capabilities and Constraints): conditions are amber. The
	// grey NOT_TESTED look would make one state read two ways on a model page.
	it('gives conditions the amber caution, not the gap look', () => {
		expect(promotionPill(doc('authorized_with_conditions', []))).toBe('conditions');
		expect(promotionPill(doc('authorized_with_conditions', []))).not.toBe('not-tested');
	});
	it('keeps escalated review red', () => {
		expect(promotionPill(doc('escalated', []))).toBe('fail');
	});
});

// A withheld report used to list its gaps as accepted surfaces, and the page
// said "Accepted, not tested" when nobody had accepted anything. Only an
// authorization with conditions accepts.
describe('accepted surfaces', () => {
	const withSurfaces = (state: string) => {
		const d = doc(state, ['NOT_TESTED']);
		d.promotion_authorization.accepted_surfaces = ['c0'];
		return d;
	};
	it('shows what an authorization with conditions accepted', () => {
		expect(acceptedSurfaces(withSurfaces('authorized_with_conditions'))).toEqual(['c0']);
	});
	it('shows nothing accepted for any other state, whatever the document lists', () => {
		for (const state of ['withheld', 'escalated', 'authorized']) {
			expect(acceptedSurfaces(withSurfaces(state)), state).toEqual([]);
		}
	});
});

describe('counts', () => {
	it('tallies the document statuses', () => {
		expect(counts(doc('authorized', ['PASS', 'PASS', 'FAIL', 'LEAD', 'NOT_TESTED']))).toEqual({
			pass: 2,
			fail: 1,
			lead: 1,
			notTested: 1
		});
	});
});

describe('count order', () => {
	it('puts what needs action first and PASS last', () => {
		expect([...countOrder]).toEqual(['fail', 'lead', 'notTested', 'pass']);
	});
});

describe('assurance levels', () => {
	it('offers only levels the engine can run', () => {
		const selectableLevels = availableLevels().filter((l) => l.available);
		expect(selectableLevels.map((l) => l.id)).toEqual(['tier1']);
	});

	it('never offers Tier 2 as selectable, it has no checks yet', () => {
		const tier2 = availableLevels().find((l) => l.id === 'tier2');
		expect(tier2).toBeDefined();
		expect(tier2?.available).toBe(false);
	});
});
