import { describe, it, expect, vi, afterEach } from 'vitest';
import { models, model, uploadAttestation, evidenceURL, ApiError } from './api';

afterEach(() => vi.unstubAllGlobals());

const json = (status: number, body: unknown) =>
	new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } });

describe('console client', () => {
	it('lists models', async () => {
		vi.stubGlobal('fetch', vi.fn(async () => json(200, { models: [{ id: 'a', stage: 'staged' }] })));
		expect((await models())[0].stage).toBe('staged');
	});

	it('never returns a stale list on failure', async () => {
		vi.stubGlobal('fetch', vi.fn(async () => json(500, { error: 'read clean: permission denied' })));
		await expect(models()).rejects.toBeInstanceOf(ApiError);
	});

	it('passes the envelope through byte for byte', async () => {
		const fetchMock = vi.fn(async () => json(200, { file: 'report.dsse.json', model: { id: 'a', stage: 'ready' } }));
		vi.stubGlobal('fetch', fetchMock);
		const env = '{"payloadType":"x", "payload":"e30=","signatures":[]}';
		await uploadAttestation('a', env);
		expect((fetchMock.mock.calls[0] as unknown as [string, RequestInit])[1].body).toBe(env);
	});

	it('carries the engine reason on a refused upload', async () => {
		vi.stubGlobal('fetch', vi.fn(async () => json(422, { error: 'signed by key abc, which is not trusted' })));
		await expect(uploadAttestation('a', '{}')).rejects.toThrow('not trusted');
	});

	it('returns the detail with a null report', async () => {
		vi.stubGlobal('fetch', vi.fn(async () => json(200, { model: { id: 'a' }, report: null, events: [] })));
		expect((await model('a')).report).toBeNull();
	});

	it('builds evidence URLs', () => {
		expect(evidenceURL('ab', 'report.dsse.json')).toBe('/api/airlock/models/ab/files/report.dsse.json');
	});
});
