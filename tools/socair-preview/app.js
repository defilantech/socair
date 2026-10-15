// The preview page: parses the Hugging Face model from the URL, mounts it as
// a filesystem over the hub (hffs.js), runs the engine (socair.wasm) on it,
// and shows the rows. Every value shown comes from the engine's report or the
// hub's listing, and is set as text, never as markup: the notes quote the
// model's own files.
import { HubFS, listRepo, previewSelection } from './hffs.js';

const $ = (id) => document.getElementById(id);
const MB = (n) => `${(n / 1e6).toFixed(n < 1e7 ? 2 : 1)} MB`;
const GB = (n) => (n >= 1e9 ? `${(n / 1e9).toFixed(1)} GB` : MB(n));

// Go reads globalThis.fs once, when it starts; each preview swaps the hub
// behind this proxy.
let current = new HubFS({ repo: 'none/none', commit: 'none', files: [] });
globalThis.fs = new Proxy({}, {
	get(_, key) {
		const v = current[key];
		return typeof v === 'function' ? v.bind(current) : v;
	}
});
let engine;
function startEngine() {
	engine ??= (async () => {
		const go = new globalThis.Go();
		globalThis.process.cwd = () => '/';
		const { instance } = await WebAssembly.instantiateStreaming(fetch('/socair.wasm'), go.importObject);
		go.run(instance);
	})();
	return engine;
}

/** org/name and a revision from a URL, a host path, or a bare repo id. */
export function parseTarget(s) {
	s = decodeURIComponent(s.trim()).replace(/^\/+/, '').replace(/^https?:\/+/, '').replace(/^(www\.)?huggingface\.co\//, '').replace(/^hf\.co\//, '');
	const m = s.match(/^([A-Za-z0-9][\w.-]*)\/([A-Za-z0-9][\w.-]*)(?:\/(?:tree|blob|resolve)\/([^/?#]+))?/);
	if (!m) return null;
	return { repo: `${m[1]}/${m[2]}`, revision: m[3] || 'main' };
}

function chip(status) {
	const s = document.createElement('span');
	s.className = `chip ${status}`;
	s.textContent = status === 'NOT_TESTED' ? 'NOT TESTED' : status;
	return s;
}

function rowsInto(tbody, checks) {
	for (const c of checks) {
		const tr = tbody.insertRow();
		tr.insertCell().append(chip(c.status));
		tr.cells[0].className = 'st';
		const td = tr.insertCell();
		const name = document.createElement('div');
		name.className = 'name';
		name.textContent = c.name;
		const notes = document.createElement('div');
		notes.className = 'notes';
		notes.textContent = c.notes || '';
		td.append(name, notes);
		if (c.status === 'PASS' && c.pass_means) {
			const means = document.createElement('div');
			means.className = 'notes';
			means.textContent = `A PASS here means: ${c.pass_means}`;
			td.append(means);
		}
	}
}

async function preview(target) {
	const { repo, revision } = target;
	$('go').disabled = true;
	$('result').classList.add('hidden');
	$('incomplete').classList.add('hidden');
	$('rows').replaceChildren();
	$('files').replaceChildren();
	const t0 = performance.now();
	const say = (s) => ($('status').textContent = s);
	try {
		say(`Listing ${repo} on Hugging Face…`);
		const [listing] = await Promise.all([listRepo(repo, revision), startEngine()]);
		if (listing.gated) {
			say(`${listing.repo} is gated on Hugging Face: its files open only to accounts that accepted its terms, and the preview takes no token. Pull it into your airlock with your HF_TOKEN instead.`);
			return;
		}
		const all = new URLSearchParams(location.search).has('all');
		const sel = all ? { include: [], kept: listing.files, left: [] } : previewSelection(listing.files);
		const hub = new HubFS({
			...listing, files: sel.kept,
			onFetch: () => say(`Reading headers and small files: ${MB(hub.fetched)} in ${hub.requests} requests…`)
		});
		current = hub;
		const [hashes] = await Promise.all([hub.hashes(), hub.warm()]);
		say('Running the checks…');
		const docs = [JSON.parse((await globalThis.socairPreview(hub.root, JSON.stringify(hashes))).json)];
		// A GGUF's own metadata (chat template, tokenizer, quant) is read by
		// a scan of the file on its own.
		const ggufs = sel.kept.filter((f) => f.path.endsWith('.gguf'));
		if (ggufs.length) docs.push(JSON.parse((await globalThis.socairPreviewFile(`${hub.root}/${ggufs[0].path}`)).json));
		const secs = ((performance.now() - t0) / 1000).toFixed(1);

		if (hub.failures.length) {
			$('failures').textContent = hub.failures.map((f) => `${f.path}: ${f.reason}`).join('\n');
			$('incomplete').classList.remove('hidden');
			say(`Stopped after ${MB(hub.fetched)} in ${secs} s.`);
			return;
		}
		const d = docs[0];
		const total = listing.files.reduce((n, f) => n + (f.size || 0), 0);
		$('model').textContent = `${listing.repo} at ${listing.commit.slice(0, 12)}`;
		const license = d.artifact.license?.id || d.artifact.license?.name;
		$('facts').textContent = [
			`${sel.kept.length} of ${listing.files.length} files (${GB(total)} in the repo)`,
			`read ${MB(hub.fetched)} in ${hub.requests} requests, ${secs} s`,
			d.artifact.architecture,
			license && `license ${license}`
		].filter(Boolean).join(' · ');
		rowsInto($('rows'), d.checks);
		for (const g of docs.slice(1)) {
			const h = document.createElement('h2');
			h.textContent = `${g.artifact.file_name}, on its own`;
			const card = document.createElement('div');
			card.className = 'card';
			const table = document.createElement('table');
			rowsInto(table.createTBody(), g.checks);
			card.append(table);
			$('files').append(h, card);
		}
		const notRun = (d.out_of_scope.not_run || []).map((n) => n.name).filter(Boolean);
		$('notrun').textContent = notRun.length ? `Not run here: ${[...new Set(notRun)].join('; ')}.` : '';
		$('digest').textContent = `sha256:${d.artifact.sha256}`;
		const name = listing.repo.split('/')[1];
		const store = `~/.socair/store/incoming/${d.artifact.sha256}`;
		$('commands').textContent = [
			`socair airlock pull --repo ${listing.repo} --revision ${listing.commit}` + (sel.include.length ? ` \\\n  --include '${sel.include.join(',')}'` : ''),
			`SOCAIR_PROVENANCE=${store}/provenance.json \\\n  socair scan ${store}/${name} > report.json`,
			`socair sign --key your.key --report report.json`
		].join('\n');
		$('left').textContent = sel.left.length ? sel.left.map((f) => `${f.path}  (${GB(f.size || 0)})`).join('\n') : 'none';
		$('result').classList.remove('hidden');
		say(`Previewed in ${secs} s.`);
	} catch (e) {
		say(`Could not preview ${repo}: ${e.message || e}`);
	} finally {
		$('go').disabled = false;
	}
}

$('form').addEventListener('submit', (e) => {
	e.preventDefault();
	const t = parseTarget($('target').value);
	if (!t) return ($('status').textContent = 'Name a model as huggingface.co/org/name.');
	history.pushState(null, '', `/huggingface.co/${t.repo}${t.revision !== 'main' ? `/tree/${t.revision}` : ''}`);
	preview(t);
});

const fromURL = parseTarget(location.pathname) || parseTarget(new URLSearchParams(location.search).get('hf') || '');
if (fromURL) {
	$('target').value = `huggingface.co/${fromURL.repo}`;
	preview(fromURL);
}
