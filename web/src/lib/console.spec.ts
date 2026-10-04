import { describe, it, expect } from 'vitest';
import {
	stageLabel,
	stageTone,
	isApprovedList,
	approvedSections,
	acceptedLine,
	reasonBeyondLabel,
	pendingHeading,
	eventTone,
	nextPurpose
} from './console';
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

describe('approved sections', () => {
	const list = [
		m({ id: 'ok', promotion_state: 'authorized' }),
		m({ id: 'late', promotion_state: 'authorized_with_conditions', acceptance_expires: '2027-03-01T00:00:00Z' }),
		m({ id: 'soon', promotion_state: 'authorized_with_conditions', acceptance_expires: '2026-10-22T00:00:00Z' }),
		m({ id: 'lapsed', stage: 'acceptance-expired' }),
		m({ id: 'bad', stage: 'does-not-verify' }),
		m({ id: 'staged', stage: 'ready', location: 'staging' })
	];
	it('puts what is not currently valid first, then conditions by soonest expiry, then approved', () => {
		const s = approvedSections(list);
		expect(s.map((x) => x.heading)).toEqual(['Not currently valid', 'Approved with conditions', 'Approved']);
		expect(s[0].models.map((x) => x.id)).toEqual(['lapsed', 'bad']);
		expect(s[1].models.map((x) => x.id)).toEqual(['soon', 'late']);
		expect(s[2].models.map((x) => x.id)).toEqual(['ok']);
	});
	it('never lists a conditional or lapsed model under Approved', () => {
		const approved = approvedSections(list).find((x) => x.key === 'approved');
		for (const x of approved?.models ?? []) expect(stageTone(x)).toBe('ok');
	});
	it('omits empty sections', () => {
		expect(approvedSections([m({ promotion_state: 'authorized' })]).map((x) => x.key)).toEqual(['approved']);
	});
});

describe('accepted gaps', () => {
	it('counts surfaces from the engine list, never by splitting a name', () => {
		expect(acceptedLine(['Hash, provenance, lineage'])).toBe('1 accepted gap');
		expect(acceptedLine(['a', 'b'])).toBe('2 accepted gaps');
	});
});

describe('stage reason', () => {
	it('drops a reason that only repeats the label', () => {
		expect(reasonBeyondLabel(m({ stage: 'acceptance-expired', stage_reason: 'acceptance expired' }))).toBe('');
		expect(
			reasonBeyondLabel(m({ stage: 'acceptance-expired', stage_reason: 'acceptance expired: on 2026-09-01' }))
		).toBe('on 2026-09-01');
	});
	it('keeps a reason that adds information', () => {
		expect(reasonBeyondLabel(m({ stage: 'does-not-verify', stage_reason: 'signature does not verify' }))).toBe(
			'signature does not verify'
		);
	});
});

describe('pending headings and events', () => {
	it('names every stage in words, not keys', () => {
		for (const s of ['ready', 'needs-acceptance', 'scanned', 'staged', 'blocked', 'acceptance-expired', 'does-not-verify']) {
			expect(pendingHeading(s)).not.toBe(s);
		}
	});
	it('a refusal is red, a conditional promotion amber, and no event is green', () => {
		expect(eventTone({ ts: '', action: 'refuse', outcome: 'refused' })).toBe('red');
		expect(eventTone({ ts: '', action: 'pull', outcome: 'refused' })).toBe('red');
		expect(eventTone({ ts: '', action: 'promote', outcome: 'conditional' })).toBe('amber');
		expect(eventTone({ ts: '', action: 'promote', outcome: 'ok' })).toBe('neutral');
	});
	it('every key-holding step says what its command does', () => {
		for (const a of ['sign', 'accept', 'promote'] as const) expect(nextPurpose(a)).not.toBe('');
	});
});
