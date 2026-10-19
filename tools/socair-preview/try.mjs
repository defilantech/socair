// Runs the preview in Node, the same code path as the page:
//   node tools/socair-preview/try.mjs org/name [revision] [--all]
// after tools/socair-preview/build.sh. Prints the rows and what was read.
import { readFile } from 'node:fs/promises';
import { pathToFileURL } from 'node:url';
import { installFS, previewRepo, IncompleteError } from './preview.js';
import { GatedError } from './hffs.js';

const args = process.argv.slice(2);
const all = args.includes('--all');
const [repo, revision = 'main'] = args.filter((a) => !a.startsWith('--'));
if (!repo) {
	console.error('usage: node try.mjs org/name [revision] [--all]');
	process.exit(2);
}
const dist = new URL('./dist/', import.meta.url);
const mount = installFS();
await import(pathToFileURL(new URL('wasm_exec.js', dist).pathname));
process.cwd = () => '/';
const go = new globalThis.Go();
const { instance } = await WebAssembly.instantiate(await readFile(new URL('socair-preview.wasm', dist)), go.importObject);
go.run(instance);

const t0 = performance.now();
try {
	const r = await previewRepo({ repo, revision, all, mount, engine: globalThis });
	const total = r.listing.files.reduce((n, f) => n + (f.size || 0), 0);
	console.log(`${r.listing.repo} at ${r.listing.commit}: ${r.listing.files.length} files, ${(total / 1e9).toFixed(2)} GB in the repo`);
	if (r.selection.include.length) console.log(`selection: --include '${r.selection.include.join(',')}' keeps ${r.selection.kept.length}, leaves out ${r.selection.left.length}`);
	console.log(`read ${(r.fetched / 1e6).toFixed(2)} MB in ${r.requests} requests, ${((performance.now() - t0) / 1000).toFixed(1)} s`);
	for (const p of r.previews) {
		if (p !== r.previews[0]) console.log(`  -- ${p.model.files[0].path}, on its own:`);
		for (const c of p.checks) console.log(`  ${c.status.padEnd(10)} ${c.name}: ${(c.notes || '').slice(0, 140)}`);
	}
	console.log(r.previews[0].notice);
	process.exit(0);
} catch (e) {
	if (e instanceof GatedError) console.log(e.message);
	else if (e instanceof IncompleteError) console.log(`PREVIEW INCOMPLETE, so no row is shown: ${e.message}`);
	else console.log(`could not preview ${repo}: ${e.message || e}`);
	process.exit(1);
}
