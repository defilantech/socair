// A read-only filesystem over one Hugging Face repo at one commit, in the
// shape Go's js/wasm runtime calls (globalThis.fs, Node's callback API). A
// read becomes HTTP range requests to the hub, cached in blocks, so the
// engine fetches only the bytes its checks read: headers, configs,
// templates, tokenizers. Nothing is written, and no file is fetched whole
// unless it is small.
//
// The repo is mounted where the Hugging Face cache would hold it,
// /hub/models--org--name/snapshots/<commit>, so the engine names it by its repo.
//
// It never sends a token: it has no way to take one. A gated or private repo
// is refused before any file is read (docs/preview.md).

const KiB = 1024;
const MiB = 1024 * KiB;

const S_IFDIR = 0o040000;
const S_IFREG = 0o100000;

function fsError(code, message) {
	const e = new Error(message || code);
	e.code = code;
	return e;
}

/** A repo the preview will not read: gated or private. */
export class GatedError extends Error {}

const REPO = /^[A-Za-z0-9][A-Za-z0-9._-]{0,95}\/[A-Za-z0-9][A-Za-z0-9._-]{0,95}$/;

/** The repo's full commit and files, from the hub's API. A gated or private
 *  repo is refused with a GatedError: the preview takes no token. */
export async function listRepo(repo, revision = 'main', { endpoint = 'https://huggingface.co' } = {}) {
	if (!REPO.test(repo) || repo.includes('..')) throw new Error(`${repo} is not an org/name repo id`);
	const url = `${endpoint}/api/models/${repo}/revision/${encodeURIComponent(revision)}?blobs=true`;
	const res = await fetch(url);
	if (res.status === 401 || res.status === 403) {
		throw new GatedError(`${repo} is gated or private on Hugging Face (it answered ${res.status}). The preview takes no token. Pull it into your airlock with your HF_TOKEN instead.`);
	}
	if (res.status === 404) throw new Error(`${repo} at ${revision}: no such repo or revision on the hub`);
	if (!res.ok) throw new Error(`the hub answered ${res.status} for ${url}`);
	const info = await res.json();
	if (info.gated || info.private) {
		throw new GatedError(`${info.id || repo} is gated on Hugging Face: its files open only to accounts that accepted its terms, and the preview takes no token. Pull it into your airlock with your HF_TOKEN instead.`);
	}
	if (!/^[0-9a-f]{40}$/.test(info.sha || '')) throw new Error(`the hub named no full commit for ${repo} at ${revision}`);
	const files = (info.siblings || []).map((s) => ({
		path: s.rfilename,
		size: s.lfs ? s.lfs.size : s.size,
		// An LFS file's oid is its SHA-256; a small file's is a git blob id.
		sha256: s.lfs ? s.lfs.sha256 : null
	}));
	return { repo: info.id || repo, commit: info.sha, files };
}

/** Translates one huggingface_hub pattern (fnmatch) to a RegExp, as the
 *  airlock's --include and --exclude read it: * matches any run of
 *  characters, slashes included; ? one; [seq] and [!seq] one in or not in
 *  seq; a pattern ending in / matches everything under that directory. */
export function globRegExp(pattern) {
	if (pattern.endsWith('/')) pattern += '*';
	let re = '';
	for (let i = 0; i < pattern.length; i++) {
		const c = pattern[i];
		if (c === '*') re += '.*';
		else if (c === '?') re += '.';
		else if (c === '[') {
			const j = pattern.indexOf(']', i + 1);
			if (j === -1) throw new Error(`an unclosed [ in ${pattern}`);
			let set = pattern.slice(i + 1, j).replace(/\\/g, '\\\\');
			if (set.startsWith('!')) set = '^' + set.slice(1);
			re += `[${set}]`;
			i = j;
		} else re += c.replace(/[.+^${}()|\\]/g, '\\$&');
	}
	return new RegExp(`^${re}$`);
}

/** The files the preview reads, and the patterns that keep them, as the
 *  airlock pull's --include:
 *  - a model served from safetensors: the selection docs/airlock.md
 *    recommends, plus any Python a loader could be told to import, so the
 *    Remote code row judges it;
 *  - a repo of GGUF quants: one quant (gguf, or Q4_K_M, or the smallest),
 *    since a quant is pulled on its own, with the small files beside it;
 *  - otherwise every file.
 *  ggufs lists the quants a page can offer instead. */
export function previewSelection(files, { gguf } = {}) {
	const paths = files.map((f) => f.path);
	const ggufs = files.filter((f) => f.path.endsWith('.gguf') && !/mmproj/i.test(f.path)).map((f) => f.path).sort();
	let include;
	if (paths.some((p) => p.endsWith('.safetensors'))) {
		include = ['*.safetensors', '*.safetensors.index.json', '*.json', '*.jinja', '*.txt', '*.model', 'README.md', 'LICENSE*', '*.py'];
	} else if (ggufs.length) {
		const size = (p) => files.find((f) => f.path === p)?.size ?? Infinity;
		const chosen = ggufs.includes(gguf) ? gguf
			: ggufs.find((p) => /q4_k_m/i.test(p)) || [...ggufs].sort((a, b) => size(a) - size(b))[0];
		// A name a pattern would read as a class or a wildcard is not
		// narrowed: every file is previewed.
		if (/[*?[\]]/.test(chosen)) return { include: [], kept: files, left: [], ggufs, gguf: chosen };
		include = [chosen, '*.json', '*.jinja', '*.txt', 'README.md', 'LICENSE*', '*.py'];
		const res = include.map(globRegExp);
		const kept = [], left = [];
		for (const f of files) (res.some((r) => r.test(f.path)) ? kept : left).push(f);
		return { include, kept, left, ggufs, gguf: chosen };
	} else {
		return { include: [], kept: files, left: [], ggufs };
	}
	const res = include.map(globRegExp);
	const kept = [], left = [];
	for (const f of files) (res.some((r) => r.test(f.path)) ? kept : left).push(f);
	return { include, kept, left, ggufs };
}

export class HubFS {
	constructor({ repo, commit, files, endpoint = 'https://huggingface.co', block = 16 * KiB,
		maxWindow = 4 * MiB, wholeBelow = 2 * MiB, perFileBudget = 64 * MiB, budget = 256 * MiB, onFetch = () => {} }) {
		Object.assign(this, { repo, commit, endpoint, block, maxWindow, wholeBelow, perFileBudget, budget, onFetch });
		// Every read that failed, by file. One failed read makes the whole
		// preview incomplete: a check that could not read a file must never
		// be shown as having read it.
		this.failures = [];
		this.root = `/hub/models--${repo.replace('/', '--')}/snapshots/${commit}`;
		this.nodes = new Map(); // absolute path -> {dir, size, path, children}
		this.fds = new Map();
		this.nextFd = 10;
		this.fetched = 0;
		this.requests = 0;
		this.byFile = new Map(); // repo path -> bytes fetched
		this.blocks = new Map(); // repo path -> Map(blockIndex -> Promise<Uint8Array>)
		this.stdout = '';
		this.constants = { O_WRONLY: 1, O_RDWR: 2, O_CREAT: 64, O_EXCL: 128, O_TRUNC: 512, O_APPEND: 1024, O_DIRECTORY: 65536 };
		this.dir('/');
		for (const f of files) {
			const abs = `${this.root}/${f.path}`;
			this.parents(abs);
			this.nodes.set(abs, { dir: false, size: f.size, path: f.path, sha256: f.sha256 });
			this.nodes.get(parentOf(abs)).children.add(baseOf(abs));
		}
	}

	dir(abs) {
		if (!this.nodes.has(abs)) {
			this.nodes.set(abs, { dir: true, size: 0, children: new Set() });
			if (abs !== '/') {
				this.parents(abs);
				this.nodes.get(parentOf(abs)).children.add(baseOf(abs));
			}
		}
	}

	parents(abs) {
		const p = parentOf(abs);
		if (p !== abs) this.dir(p);
	}

	node(path) {
		return this.nodes.get(normalize(path));
	}

	statOf(node, ino = 1) {
		const now = Date.now();
		return {
			dev: 1, ino, mode: node.dir ? S_IFDIR | 0o555 : S_IFREG | 0o444, nlink: 1, uid: 0, gid: 0, rdev: 0,
			size: node.size, blksize: 4096, blocks: Math.ceil(node.size / 512),
			atimeMs: now, mtimeMs: now, ctimeMs: now,
			isDirectory: () => node.dir
		};
	}

	url(path) {
		const enc = path.split('/').map(encodeURIComponent).join('/');
		return `${this.endpoint}/${this.repo}/resolve/${this.commit}/${enc}`;
	}

	/** Fetches bytes [start, end) of a file, from the cache in blocks. */
	async bytes(node, start, end) {
		end = Math.min(end, node.size);
		if (start >= end) return new Uint8Array(0);
		const whole = node.size <= this.wholeBelow;
		const size = whole ? node.size : this.block;
		const first = Math.floor(start / size), last = Math.floor((end - 1) / size);
		let cache = this.blocks.get(node.path);
		if (!cache) this.blocks.set(node.path, (cache = new Map()));
		// One request for each run of missing blocks.
		for (let i = first; i <= last; ) {
			if (cache.has(i)) { i++; continue; }
			let j = i;
			while (j + 1 <= last && !cache.has(j + 1)) j++;
			const from = i * size, to = Math.min((j + 1) * size, node.size);
			const run = this.fetchRange(node, from, to);
			for (let k = i; k <= j; k++) {
				const off = (k - i) * size;
				const blk = run.then((b) => b.subarray(off, Math.min(off + size, b.length)));
				// A failed fetch is reported by the read that awaits it; the
				// other blocks of the same run must not count as unhandled.
				blk.catch(() => {});
				cache.set(k, blk);
			}
			i = j + 1;
		}
		const out = new Uint8Array(end - start);
		for (let i = first; i <= last; i++) {
			const b = await cache.get(i);
			const bStart = i * size;
			const from = Math.max(start, bStart), to = Math.min(end, bStart + b.length);
			out.set(b.subarray(from - bStart, to - bStart), from - start);
		}
		return out;
	}

	async fetchRange(node, from, to) {
		const had = this.byFile.get(node.path) || 0;
		if (had + (to - from) > this.perFileBudget || this.fetched + (to - from) > this.budget) {
			throw fsError('EIO', `${node.path}: the preview's read budget would be passed`);
		}
		this.byFile.set(node.path, had + (to - from));
		this.fetched += to - from;
		this.requests++;
		const headers = { Range: `bytes=${from}-${to - 1}` };
		const t0 = performance.now();
		// The hub answers a file's URL with a redirect to its storage; later
		// ranges of the same file go to where it redirected, which halves
		// each request's round trips. An expired one falls back to the hub.
		this.direct ??= new Map();
		let res;
		const direct = this.direct.get(node.path);
		if (direct) res = await fetch(direct, { headers });
		if (!res || (res.status !== 206 && res.status !== 200)) {
			res = await fetch(this.url(node.path), { headers });
			if (res.redirected) this.direct.set(node.path, res.url);
		}
		if (res.status !== 206 && res.status !== 200) throw fsError('EIO', `${node.path}: the hub answered ${res.status}`);
		let b = new Uint8Array(await res.arrayBuffer());
		if (res.status === 200 && (from > 0 || b.length > to - from)) b = b.subarray(from, to);
		this.onFetch({ path: node.path, from, to, ms: performance.now() - t0 });
		return b;
	}

	/** Fills the cache, in parallel, with what the checks will read first:
	 *  every safetensors header (its 8-byte length, then the JSON) and the
	 *  start of every GGUF (its metadata). It only saves round trips: the
	 *  engine still reads what it reads, and a miss is fetched on demand. */
	async warm(concurrency = 8) {
		const jobs = [];
		for (const n of this.nodes.values()) {
			if (n.dir || n.size <= this.wholeBelow) continue;
			if (n.path.endsWith('.safetensors')) {
				jobs.push(async () => {
					const head = await this.bytes(n, 0, Math.min(n.size, 256 * KiB));
					if (head.length < 8) return;
					const len = Number(new DataView(head.buffer, head.byteOffset, 8).getBigUint64(0, true));
					if (len > 0 && 8 + len <= Math.min(n.size, 64 * MiB)) await this.bytes(n, 0, 8 + len);
				});
			} else if (n.path.endsWith('.gguf')) {
				jobs.push(() => this.bytes(n, 0, Math.min(n.size, 4 * MiB)));
			}
		}
		const queue = [...jobs];
		await Promise.all(Array.from({ length: Math.min(concurrency, queue.length) }, async () => {
			while (queue.length) {
				try { await queue.shift()(); } catch { /* the read that needs it reports it */ }
			}
		}));
	}

	/** Every file's SHA-256 by its repo path: an LFS file's as the hub states
	 *  it, and a small file's from its bytes, fetched whole (the scan reads
	 *  them anyway: configs, templates, tokenizers, the model card). */
	async hashes() {
		const out = {};
		await Promise.all([...this.nodes.values()].filter((n) => !n.dir).map(async (n) => {
			if (n.sha256) { out[n.path] = n.sha256; return; }
			const b = await this.bytes(n, 0, n.size);
			const d = new Uint8Array(await crypto.subtle.digest('SHA-256', b));
			out[n.path] = [...d].map((x) => x.toString(16).padStart(2, '0')).join('');
		}));
		return out;
	}

	// ---- the fs API Go's syscall/fs_js.go calls ----

	writeSync(fd, buf) {
		this.stdout += new TextDecoder().decode(buf);
		const nl = this.stdout.lastIndexOf('\n');
		if (nl !== -1) {
			console.log(this.stdout.slice(0, nl));
			this.stdout = this.stdout.slice(nl + 1);
		}
		return buf.length;
	}
	write(fd, buf, offset, length, position, cb) {
		if (fd === 1 || fd === 2) {
			if (offset !== 0 || length !== buf.length || position !== null) return cb(fsError('ENOSYS'));
			return cb(null, this.writeSync(fd, buf));
		}
		cb(fsError('EBADF'));
	}
	open(path, flags, mode, cb) {
		const node = this.node(path);
		if (!node) return cb(fsError('ENOENT', path));
		if (flags & (this.constants.O_WRONLY | this.constants.O_RDWR | this.constants.O_CREAT)) return cb(fsError('EACCES', path));
		const fd = this.nextFd++;
		this.fds.set(fd, { node, pos: 0 });
		cb(null, fd);
	}
	close(fd, cb) { this.fds.delete(fd); cb(null); }
	fstat(fd, cb) {
		const f = this.fds.get(fd);
		if (!f) return cb(fsError('EBADF'));
		cb(null, this.statOf(f.node, fd));
	}
	stat(path, cb) {
		const node = this.node(path);
		if (!node) return cb(fsError('ENOENT', path));
		cb(null, this.statOf(node));
	}
	lstat(path, cb) { this.stat(path, cb); }
	readdir(path, cb) {
		const node = this.node(path);
		if (!node) return cb(fsError('ENOENT', path));
		if (!node.dir) return cb(fsError('ENOTDIR', path));
		cb(null, [...node.children].sort());
	}
	read(fd, buffer, offset, length, position, cb) {
		const f = this.fds.get(fd);
		if (!f) return cb(fsError('EBADF'));
		if (f.node.dir) return cb(fsError('EISDIR'));
		const at = position === null || position === undefined ? f.pos : position;
		// A read where the last one ended doubles the window, up to maxWindow;
		// any other starts small. A read is cut to the window (a short read,
		// which Go's readers take), so a parser that seeks from header to
		// header fetches a block at each, not the buffer it asked to fill.
		f.window = at === f.end ? Math.min((f.window || this.block) * 2, this.maxWindow) : this.block;
		const n = f.node.size <= this.wholeBelow ? length : Math.min(length, f.window);
		this.bytes(f.node, at, at + n).then(
			(b) => {
				buffer.set(b, offset);
				if (position === null || position === undefined) f.pos += b.length;
				f.end = at + b.length;
				cb(null, b.length);
			},
			(e) => {
				this.failures.push({ path: f.node.path, reason: e.message || String(e) });
				cb(e.code ? e : fsError('EIO', String(e)));
			}
		);
	}
	fsync(fd, cb) { cb(null); }
	readlink(path, cb) { cb(fsError('EINVAL', path)); }
	chmod(p, m, cb) { cb(fsError('EACCES')); }
	chown(p, u, g, cb) { cb(fsError('EACCES')); }
	fchmod(fd, m, cb) { cb(fsError('EACCES')); }
	fchown(fd, u, g, cb) { cb(fsError('EACCES')); }
	lchown(p, u, g, cb) { cb(fsError('EACCES')); }
	ftruncate(fd, l, cb) { cb(fsError('EACCES')); }
	truncate(p, l, cb) { cb(fsError('EACCES')); }
	link(p, l, cb) { cb(fsError('EACCES')); }
	symlink(p, l, cb) { cb(fsError('EACCES')); }
	mkdir(p, m, cb) { cb(fsError('EACCES')); }
	rename(a, b, cb) { cb(fsError('EACCES')); }
	rmdir(p, cb) { cb(fsError('EACCES')); }
	unlink(p, cb) { cb(fsError('EACCES')); }
	utimes(p, a, m, cb) { cb(fsError('EACCES')); }
}

function normalize(p) {
	const out = [];
	for (const s of p.split('/')) {
		if (s === '' || s === '.') continue;
		if (s === '..') out.pop();
		else out.push(s);
	}
	return '/' + out.join('/');
}
const parentOf = (abs) => normalize(abs + '/..');
const baseOf = (abs) => abs.slice(abs.lastIndexOf('/') + 1);
