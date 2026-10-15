// Runs the preview in Node, the same code path as the page:
//   node try.mjs org/name [revision] [--all]
import { readFile } from 'node:fs/promises';
import { pathToFileURL } from 'node:url';
import { HubFS, listRepo, previewSelection } from './hffs.js';

const args = process.argv.slice(2);
const all = args.includes('--all');
const [repo, revision = 'main'] = args.filter((a) => !a.startsWith('--'));
const dist = new URL('./dist/', import.meta.url);
const t0 = performance.now();
const listing = await listRepo(repo, revision);
const sel = all ? { include: [], kept: listing.files, left: [] } : previewSelection(listing.files);
const hub = new HubFS({ ...listing, files: sel.kept,
	onFetch: process.env.TRACE ? (e) => console.error(`fetch ${e.path} [${e.from}, ${e.to}) ${e.ms.toFixed(0)}ms`) : undefined });
globalThis.fs = hub;
await import(pathToFileURL(new URL('wasm_exec.js', dist).pathname));
process.cwd = () => '/';
const go = new globalThis.Go();
const { instance } = await WebAssembly.instantiate(await readFile(new URL('socair.wasm', dist)), go.importObject);
go.run(instance);

const [hashes] = await Promise.all([hub.hashes(), hub.warm()]);
const out = await globalThis.socairPreview(hub.root, JSON.stringify(hashes));
const docs = [JSON.parse(out.json)];
// A GGUF's own metadata (chat template, tokenizer, quant) is read by a scan of
// the file on its own; the directory scan names it as not run.
for (const f of sel.kept.filter((f) => f.path.endsWith('.gguf')).slice(0, 1)) {
	docs.push(JSON.parse((await globalThis.socairPreviewFile(`${hub.root}/${f.path}`)).json));
}
if (process.env.OUT) (await import('node:fs')).writeFileSync(process.env.OUT, JSON.stringify(docs[0]));
const total = listing.files.reduce((n, f) => n + (f.size || 0), 0);
console.log(`${docs[0].artifact.name} @ ${listing.commit.slice(0, 12)}: ${listing.files.length} files, ${(total / 1e9).toFixed(2)} GB in the repo`);
if (sel.include.length) console.log(`selection: --include '${sel.include.join(',')}' keeps ${sel.kept.length}, leaves out ${sel.left.length}: ${sel.left.map((f) => f.path).join(' ')}`);
console.log(`fetched ${(hub.fetched / 1e6).toFixed(2)} MB in ${hub.requests} requests, ${((performance.now() - t0) / 1000).toFixed(1)} s`);
if (hub.failures.length) {
	console.log(`PREVIEW INCOMPLETE: ${hub.failures.length} read(s) failed, so no row is shown`);
	for (const f of hub.failures.slice(0, 5)) console.log(`  ${f.path}: ${f.reason}`);
	process.exit(1);
}
for (const d of docs) {
	if (d !== docs[0]) console.log(`  -- ${d.artifact.file_name} on its own:`);
	for (const c of d.checks) console.log(`  ${c.status.padEnd(10)} ${c.name}: ${(c.notes || '').slice(0, 140)}`);
}
console.log('  promotion with no policy (not shown on the page):', docs[0].promotion_authorization?.state);
process.exit(0);
