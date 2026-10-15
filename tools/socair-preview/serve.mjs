// A local server for the built preview (dist/), routing /huggingface.co/*
// to the page as socair.ai would: node serve.mjs [port]
import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import { extname, normalize } from 'node:path';

const port = Number(process.argv[2] || 4321);
const dist = new URL('./dist/', import.meta.url).pathname;
const types = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript', '.wasm': 'application/wasm' };

createServer(async (req, res) => {
	let path = normalize(decodeURIComponent(new URL(req.url, 'http://x').pathname));
	if (path === '/' || !extname(path) || path.startsWith('/huggingface.co/') || path.startsWith('/https:')) path = '/index.html';
	try {
		const body = await readFile(dist + path.replace(/^\/+/, ''));
		res.writeHead(200, { 'content-type': types[extname(path)] || 'application/octet-stream' });
		res.end(body);
	} catch {
		res.writeHead(404).end('not found');
	}
}).listen(port, '127.0.0.1', () => console.log(`http://127.0.0.1:${port}/huggingface.co/HuggingFaceTB/SmolLM2-135M-Instruct`));
