import { describe, it, expect } from 'vitest';
import { runScan, canDownload } from './run';
import type { Document } from './api';

const ok = { schema_version: 'socair.report/v1' } as unknown as Document;

describe('runScan', () => {
	it('resolves to done with a report on success', async () => {
		const state = await runScan(async () => ok, '/m.gguf');
		expect(state.kind).toBe('done');
		expect(canDownload(state)).toBe(true);
	});

	it('surfaces an engine failure as a failed state, never a false success', async () => {
		const state = await runScan(async () => {
			throw new Error('engine unreachable');
		}, '/m.gguf');
		expect(state.kind).toBe('failed');
		expect(state.kind === 'failed' && state.error).toContain('unreachable');
		expect(canDownload(state)).toBe(false);
	});

	it('surfaces a scan rejected mid-run, and offers no download', async () => {
		const state = await runScan(async () => {
			throw new DOMException('The operation was aborted.', 'AbortError');
		}, '/m.gguf');
		expect(state.kind).toBe('failed');
		expect(canDownload(state)).toBe(false);
	});

	it('refuses an empty path without calling the engine', async () => {
		let called = false;
		const state = await runScan(async () => {
			called = true;
			return ok;
		}, '   ');
		expect(called).toBe(false);
		expect(state.kind).toBe('failed');
		expect(canDownload(state)).toBe(false);
	});
});
