// Runs Socair's preview of a Hugging Face model (docs/preview.md): lists the
// repo at a full commit, mounts the files the preview reads as a filesystem
// over the hub (hffs.js), and runs the engine (cmd/socair-preview, already
// started) on it. The same code runs in a page and in Node (try.mjs).
//
// All or nothing: if any read fails, no preview is returned, because a check
// that could not read a file must never look like it did.
import { HubFS, listRepo, previewSelection } from './hffs.js';

/** org/name and a revision from a URL, a host path, or a bare repo id; null
 *  when it names none. */
export function parseTarget(s) {
	s = String(s || '').trim().replace(/^\/+/, '').replace(/^https?:\/+/, '').replace(/^(www\.)?huggingface\.co\//, '').replace(/^hf\.co\//, '');
	try { s = decodeURIComponent(s); } catch { return null; }
	const m = s.match(/^([A-Za-z0-9][\w.-]*)\/([A-Za-z0-9][\w.-]*)(?:\/(?:tree|blob|resolve)\/([^/?#]+))?\/?(?:[?#].*)?$/);
	if (!m || m[1].includes('..') || m[2].includes('..')) return null;
	return { repo: `${m[1]}/${m[2]}`, revision: m[3] || 'main' };
}

/** Swaps the repo Go's runtime reads through. Go reads globalThis.fs once,
 *  when it starts, so the proxy stays and the hub behind it changes. */
export function installFS() {
	let current = new HubFS({ repo: 'none/none', commit: '0'.repeat(40), files: [] });
	globalThis.fs = new Proxy({}, {
		get(_, key) {
			const v = current[key];
			return typeof v === 'function' ? v.bind(current) : v;
		}
	});
	return (hub) => { current = hub; };
}

/**
 * Previews repo at revision (gguf names the quant to read in a repo of
 * GGUF quants). engine is { socairPreview, socairPreviewGGUF }
 * from the started wasm; mount is installFS's result. Returns
 * { listing, selection, previews, fetched, requests } or throws: a
 * GatedError for a gated or private repo, an IncompleteError when a read
 * failed.
 */
export async function previewRepo({ repo, revision = 'main', all = false, gguf, engine, mount, onProgress = () => {} }) {
	onProgress({ phase: 'listing' });
	const listing = await listRepo(repo, revision);
	const selection = all ? { include: [], kept: listing.files, left: [], ggufs: [] } : previewSelection(listing.files, { gguf });
	const hub = new HubFS({ ...listing, files: selection.kept,
		onFetch: () => onProgress({ phase: 'reading', fetched: hub.fetched, requests: hub.requests }) });
	mount(hub);
	const source = JSON.stringify({ hub: 'huggingface.co', repo: listing.repo, commit: listing.commit });
	const [hashes] = await Promise.all([hub.hashes(), hub.warm()]);
	onProgress({ phase: 'checking', fetched: hub.fetched, requests: hub.requests });
	const previews = [];
	let failed;
	try {
		previews.push(JSON.parse(await engine.socairPreview(hub.root, source, JSON.stringify(hashes))));
		// A GGUF's own metadata (chat template, tokenizer, quant) is read by
		// a preview of the file on its own.
		const gguf = selection.kept.find((f) => f.path.endsWith('.gguf'));
		if (gguf) previews.push(JSON.parse(await engine.socairPreviewGGUF(`${hub.root}/${gguf.path}`, source, hashes[gguf.path])));
	} catch (e) {
		failed = e;
	}
	if (hub.failures.length || failed) {
		throw new IncompleteError(hub.failures.length ? hub.failures : [{ path: listing.repo, reason: String(failed?.message || failed) }],
			{ fetched: hub.fetched, requests: hub.requests });
	}
	return { listing, selection, previews, fetched: hub.fetched, requests: hub.requests };
}

/** A preview that did not finish: no row is shown. */
export class IncompleteError extends Error {
	constructor(failures, stats) {
		super(`the preview could not read ${failures.map((f) => `${f.path} (${f.reason})`).join('; ')}`);
		this.failures = failures;
		this.stats = stats;
	}
}

/** The airlock commands that pull, scan, and sign the same files at the same
 *  commit, for real. */
export function airlockCommands(listing, selection, digest) {
	const name = listing.repo.split('/')[1];
	const store = `~/.socair/store/incoming/${digest}`;
	return [
		`socair airlock pull --repo ${listing.repo} --revision ${listing.commit}` +
			(selection.include.length ? ` \\\n  --include '${selection.include.join(',')}'` : ''),
		`SOCAIR_PROVENANCE=${store}/provenance.json \\\n  socair scan ${store}/${name} > report.json`,
		'socair sign --key your.key --report report.json'
	].join('\n');
}
