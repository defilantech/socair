import { describe, it, expect } from 'vitest';
import { shortDate, shortTime, relative } from './when';

describe('dates', () => {
	it('formats an ISO timestamp as a short UTC date', () => {
		expect(shortDate('2026-10-22T22:37:10Z')).toBe('22 Oct 2026');
		expect(shortDate('2027-01-01T00:00:00Z')).toBe('1 Jan 2027');
	});
	it('formats a log time with minutes and the zone', () => {
		expect(shortTime('2026-10-04T09:05:59.123456Z')).toBe('4 Oct 2026, 09:05 UTC');
	});
	it('returns what it cannot parse unchanged, and nothing for nothing', () => {
		expect(shortDate('not a date')).toBe('not a date');
		expect(shortDate(undefined)).toBe('');
		expect(relative('not a date')).toBe('');
	});
	it('says how far away an expiry is', () => {
		const now = new Date('2026-10-04T12:00:00Z');
		expect(relative('2026-10-22T12:00:00Z', now)).toBe('in 18 days');
		expect(relative('2026-09-30T12:00:00Z', now)).toBe('4 days ago');
		expect(relative('2026-10-04T18:00:00Z', now)).toBe('today');
		expect(relative('2026-10-05T12:00:00Z', now)).toBe('tomorrow');
		expect(relative('2026-10-03T12:00:00Z', now)).toBe('yesterday');
	});
});
