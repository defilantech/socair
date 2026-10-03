import { defineConfig } from 'vitest/config';
import adapter from '@sveltejs/adapter-static';
import { sveltekit } from '@sveltejs/kit/vite';

export default defineConfig({
	plugins: [
		sveltekit({
			compilerOptions: {
				// Force runes mode for the project, except for libraries. Can be removed in svelte 6.
				runes: ({ filename }) => filename.split(/[/\\]/).includes('node_modules') ? undefined : true
			},

			// The wizard has no server-side logic, so it builds to static files
			// that `socair serve` serves. The 200.html fallback answers any client
			// route.
			adapter: adapter({ fallback: '200.html' })
		})
	],
	// Dev mode: the wizard on :5173 talks to a local `socair serve` through
	// this proxy. The engine refuses a request whose Origin is not its own
	// (docs/api.md), so the proxy rewrites the Origin only when it is this dev
	// server's own; a request from any other site keeps its Origin and is
	// still refused by the engine. SOCAIR_API points at a non-default engine.
	server: {
		proxy: {
			'/api': {
				target: process.env.SOCAIR_API ?? 'http://127.0.0.1:8080',
				changeOrigin: true,
				configure: (proxy, options) => {
					proxy.on('proxyReq', (proxyReq, req) => {
						const origin = req.headers.origin;
						if (origin && origin === `http://${req.headers.host}`) {
							proxyReq.setHeader('origin', String(options.target));
						}
					});
				}
			}
		}
	},
	test: {
		expect: { requireAssertions: true },
		projects: [
			{
				extends: './vite.config.ts',
				test: {
					name: 'server',
					environment: 'node',
					include: ['src/**/*.{test,spec}.{js,ts}'],
					exclude: ['src/**/*.svelte.{test,spec}.{js,ts}']
				}
			}
		]
	}
});
