import { describe, it, expect } from 'vitest';
import { stageLabel, stageTone, isApprovedList } from './console';
import type { Model } from './api';

const m = (over: Partial<Model>): Model => ({
	id: 'a',
	name: 'n',
	location: 'clean',
	stage: 'approved',
	next: { action: 'none' },
	...over
});

describe('display rules', () => {
	it('conditional approval is amber, never green', () => {
		const c = m({ promotion_state: 'authorized_with_conditions', acceptance_expires: '2027-01-31T00:00:00Z' });
		expect(stageTone(c)).toBe('amber');
		expect(stageLabel(c)).toContain('conditions');
	});
	it('only a clean authorization is green', () => {
		expect(stageTone(m({ promotion_state: 'authorized' }))).toBe('ok');
	});
	it('what does not verify, an expired acceptance, and blocked are red', () => {
		for (const stage of ['does-not-verify', 'acceptance-expired', 'blocked'] as const) {
			expect(stageTone(m({ stage }))).toBe('red');
		}
	});
	it('labels an acceptance that expires soon', () => {
		expect(
			stageLabel(m({ promotion_state: 'authorized_with_conditions', expires_soon: true, acceptance_expires: 'x' }))
		).toContain('expires soon');
	});
	it('needs-acceptance never reads as approved', () => {
		const n = m({ stage: 'needs-acceptance', location: 'staging' });
		expect(stageTone(n)).not.toBe('ok');
		expect(isApprovedList(n)).toBe(false);
	});
	it('the approved list holds clean entries only', () => {
		expect(isApprovedList(m({ stage: 'does-not-verify' }))).toBe(true);
		expect(isApprovedList(m({ stage: 'ready', location: 'staging' }))).toBe(false);
	});
});
