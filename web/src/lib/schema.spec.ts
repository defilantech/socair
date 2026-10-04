import { describe, it, expect } from 'vitest';
import { CHECK_STATUSES, type CheckResult, type Document } from './api';
import schema from '../../../docs/report-schema/v1.json';
import golden from '../../../testdata/report.json';
import demo from '../../../internal/demo/report.json';

// JSON imports widen string literals, so status is checked at runtime against
// CHECK_STATUSES and every other field is checked by svelte-check through
// these assignments: a field whose type the wizard declares differently, or a
// required field the engine stops sending, fails the type check.
type Wide = Omit<Document, 'checks'> & {
	checks: (Omit<CheckResult, 'status' | 'severity'> & { status: string; severity?: string })[];
};
const docs: Record<string, Wide> = { golden, demo };

describe('report contract', () => {
	it('the wizard status enum is the schema enum', () => {
		const enumInSchema = schema.properties.checks.items.properties.status.enum;
		expect([...CHECK_STATUSES].sort()).toEqual([...enumInSchema].sort());
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
