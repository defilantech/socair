import { describe, it, expect } from 'vitest';
import { MEASUREMENT_OUTCOMES, type Document, type Measurement } from './api';
import {
	statusPill,
	promotionLabel,
	promotionPill,
	acceptedSurfaces,
	counts,
	countOrder,
	availableLevels,
	measurementPill,
	measurementSummary,
	nodeClassFacts,
	shortHash
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
	// Conditions are amber. The grey NOT_TESTED look would make one state read
	// two ways on a model page.
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

const measurement = (outcome: Measurement['outcome']): Measurement => ({
	check: 'Serving-stack differential (Tier 2)',
	suite: 's',
	suite_version: '1',
	dataset_digest: 'sha256:' + 'a'.repeat(64),
	scorer: 'deterministic',
	n: 8,
	score: 0.75,
	ci95: [0.4, 0.93],
	metrics: { kl: 0.02, agreement: 0.75 },
	decoding: { temperature: 0, top_p: 1, max_tokens: 32, seed: 0 },
	engine: 'vllm 0.11.0',
	node_class: 'sha256:' + 'b'.repeat(64),
	started_utc: '2026-10-09T10:00:00Z',
	ended_utc: '2026-10-09T10:01:00Z',
	outcome
});

describe('Tier 2 measurements', () => {
	it('never renders a measurement as a pass', () => {
		for (const o of MEASUREMENT_OUTCOMES) expect(measurementPill(o), o).not.toBe('pass');
	});
	it('keeps a measurement that found nothing apart from a gap', () => {
		expect(measurementPill('measured')).toBe('measured');
		expect(measurementPill('measured')).not.toBe('not-tested');
		expect(measurementPill('error')).toBe('not-tested');
	});
	it('gives LEAD and FAIL their own treatments', () => {
		expect(measurementPill('lead')).toBe('lead');
		expect(measurementPill('fail')).toBe('fail');
	});
	it('states the numbers the engine sent', () => {
		expect(measurementSummary(measurement('measured'))).toBe(
			'score 0.75 (95% CI 0.4 to 0.93), n=8, agreement 0.75, kl 0.02'
		);
	});
	// A measurement is not a check row; only the rows it raised are counted.
	it('adds nothing to the tally', () => {
		const d = doc('authorized', ['PASS']);
		d.tier2 = { statement: 's', helper: 'h', node_classes: [], measurements: [measurement('measured')] };
		expect(counts(d)).toEqual({ pass: 1, fail: 0, lead: 0, notTested: 0 });
	});
	it('names the node-class fields that were not reported, and unknown is not false', () => {
		const f = nodeClassFacts({
			schema: 'socair.nodeclass/v1', gpu_model: 'NVIDIA H100', compute_capability: '', gpu_count: 8,
			interconnect: '', driver: '', vbios: '', ecc: null, mig: '', cc_mode: '', cuda: '', cublas: '',
			cudnn: '', nccl: '', container_image_digest: '', engine_name: 'vllm', engine_version: '',
			engine_commit: '', dtype: '', weight_quantization: '', kv_cache_quantization: '',
			tensor_parallel_size: 0, pipeline_parallel_size: 0, expert_parallel_size: 0, attention_backend: '',
			cuda_graphs: false, torch_compile: null, eager: null, batch_invariant: null, prefix_caching: null,
			chunked_prefill: null, speculative_decoding: '', env: { B: '2', A: '1' }
		});
		expect(f.reported).toEqual(['gpu_model NVIDIA H100', 'gpu_count 8', 'engine_name vllm', 'cuda_graphs false', 'env A=1, B=2']);
		expect(f.unreported).toContain('ecc');
		expect(f.unreported).not.toContain('cuda_graphs');
		expect(f.unreported).not.toContain('schema');
	});
	it('abbreviates a digest', () => {
		expect(shortHash('sha256:' + 'c'.repeat(64))).toBe('sha256:' + 'c'.repeat(12));
		expect(shortHash('abc')).toBe('abc');
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
