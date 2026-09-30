import { describe, it, expect, vi, afterEach } from 'vitest';
import { scan, renderReport, health, ApiError } from './api';

afterEach(() => vi.unstubAllGlobals());

function jsonResponse(status: number, body: unknown): Response {
	return new Response(JSON.stringify(body), {
		status,
		headers: { 'content-type': 'application/json' }
	});
}

describe('scan', () => {
	it('returns the engine document on 200', async () => {
		vi.stubGlobal(
			'fetch',
			vi.fn(async () => jsonResponse(200, { report: { schema_version: 'socair.report/v1' } }))
		);
		const d = await scan('/models/m.gguf');
		expect(d.schema_version).toBe('socair.report/v1');
	});

	it('throws the engine message on a non-2xx, never a partial success', async () => {
		vi.stubGlobal(
			'fetch',
			vi.fn(async () => jsonResponse(422, { error: 'open /nope: no such file or directory' }))
		);
		await expect(scan('/nope')).rejects.toThrow('open /nope: no such file or directory');
		await expect(scan('/nope')).rejects.toBeInstanceOf(ApiError);
	});

	it('does not treat a 200 with no report as a success', async () => {
		vi.stubGlobal('fetch', vi.fn(async () => jsonResponse(200, {})));
		await expect(scan('/x')).rejects.toThrow('no report');
	});
});

describe('renderReport', () => {
	it('returns bytes on 200', async () => {
		vi.stubGlobal(
			'fetch',
			vi.fn(
				async () =>
					new Response(new Uint8Array([0x25, 0x50, 0x44, 0x46]), {
						status: 200,
						headers: { 'content-type': 'application/pdf' }
					})
			)
		);
		const blob = await renderReport({} as never, 'pdf');
		expect(blob.size).toBeGreaterThan(0);
	});

	it('throws on a refused render', async () => {
		vi.stubGlobal(
			'fetch',
			vi.fn(async () => jsonResponse(422, { error: 'report did not validate' }))
		);
		await expect(renderReport({} as never, 'html')).rejects.toThrow('did not validate');
	});
});

describe('health', () => {
	it('surfaces a degraded engine', async () => {
		vi.stubGlobal(
			'fetch',
			vi.fn(async () => jsonResponse(503, { error: 'airlock store not initialized' }))
		);
		await expect(health()).rejects.toThrow('not initialized');
	});
});
