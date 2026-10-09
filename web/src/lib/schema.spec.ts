import { describe, it, expect } from 'vitest';
import {
	CHECK_STATUSES,
	MEASUREMENT_OUTCOMES,
	type CheckResult,
	type Document,
	type Measurement,
	type NodeClass,
	type Tier2
} from './api';
import schema from '../../../docs/report-schema/v1.json';
import golden from '../../../testdata/report.json';
import goldenTier2 from '../../../testdata/report-tier2.json';
import demo from '../../../internal/demo/report.json';

// JSON imports widen string literals, so status and outcome are checked at
// runtime against CHECK_STATUSES and MEASUREMENT_OUTCOMES, and every other
// field is checked by svelte-check through these assignments: a field whose
// type the wizard declares differently, or a required field the engine stops
// sending, fails the type check. Metrics are widened too: an array of
// measurements with different metric names imports as optional keys.
type WideMeasurement = Omit<Measurement, 'outcome' | 'metrics'> & {
	outcome: string;
	metrics?: Record<string, number | undefined>;
};
type Wide = Omit<Document, 'checks' | 'tier2'> & {
	checks: (Omit<CheckResult, 'status' | 'severity'> & { status: string; severity?: string })[];
	tier2?: Omit<Tier2, 'measurements'> & { measurements: WideMeasurement[] };
};
const docs: Record<string, Wide> = { golden, goldenTier2, demo };

describe('report contract', () => {
	it('the wizard status enum is the schema enum', () => {
		const enumInSchema = schema.properties.checks.items.properties.status.enum;
		expect([...CHECK_STATUSES].sort()).toEqual([...enumInSchema].sort());
	});

	it('the wizard measurement outcomes are the schema enum, with no pass', () => {
		const enumInSchema = schema.properties.tier2.properties.measurements.items.properties.outcome.enum;
		expect([...MEASUREMENT_OUTCOMES].sort()).toEqual([...enumInSchema].sort());
		expect(MEASUREMENT_OUTCOMES as readonly string[]).not.toContain('pass');
	});

	it('the wizard node class names every field of the schema record', () => {
		const fields = schema.properties.tier2.properties.node_classes.items.properties.facts.required;
		const sample: Record<keyof NodeClass, unknown> = {
			schema: '', gpu_model: '', compute_capability: '', gpu_count: 0, interconnect: '', driver: '', vbios: '',
			ecc: null, mig: '', cc_mode: '', cuda: '', cublas: '', cudnn: '', nccl: '', container_image_digest: '',
			engine_name: '', engine_version: '', engine_commit: '', dtype: '', weight_quantization: '',
			kv_cache_quantization: '', tensor_parallel_size: 0, pipeline_parallel_size: 0, expert_parallel_size: 0,
			attention_backend: '', cuda_graphs: null, torch_compile: null, eager: null, batch_invariant: null,
			prefix_caching: null, chunked_prefill: null, speculative_decoding: '', env: null
		};
		expect(Object.keys(sample).sort()).toEqual([...fields].sort());
	});

	it('the golden and demo bounded statements are the schema sentence for their rows', () => {
		const [noIndicators, indicators, tier2NoIndicators, tier2Indicators] = schema.properties.bounded_statement.enum;
		for (const [name, d] of Object.entries(docs)) {
			const flagged = d.checks.some((c) => c.status === 'FAIL' || c.status === 'LEAD');
			const want = d.tier2 ? (flagged ? tier2Indicators : tier2NoIndicators) : flagged ? indicators : noIndicators;
			expect(d.bounded_statement, name).toBe(want);
		}
	});

	it('the Tier 2 golden fits the wizard type and has no pass', () => {
		const t2 = goldenTier2.tier2;
		expect(t2).toBeDefined();
		for (const m of t2.measurements) {
			expect(MEASUREMENT_OUTCOMES as readonly string[], m.check).toContain(m.outcome);
		}
		// Every LEAD or FAIL measurement has its check row with that status.
		for (const m of t2.measurements.filter((x) => x.outcome === 'lead' || x.outcome === 'fail')) {
			const row = goldenTier2.checks.find((c) => c.name === m.check);
			expect(row?.status, m.check).toBe(m.outcome.toUpperCase());
		}
	});

	it('the golden and demo documents fit the wizard type', () => {
		for (const [name, d] of Object.entries(docs)) {
			expect(d.schema_version, name).toBe('socair.report/v1');
			const severities = schema.properties.checks.items.properties.severity.enum as string[];
			for (const c of d.checks) {
				expect(CHECK_STATUSES as readonly string[], `${name}: ${c.name}`).toContain(c.status);
				if (c.severity !== undefined) expect(severities, `${name}: ${c.name}`).toContain(c.severity);
			}
		}
	});
});
