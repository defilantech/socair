// The wizard's run state.
//
// A scan is a single transition: running, then done with a report, or failed
// with the engine's own message. There is no partial success and no stale
// report: a failure produces a failed state and nothing downloadable.

import type { Document } from './api';

export type RunState =
	| { kind: 'idle' }
	| { kind: 'running' }
	| { kind: 'done'; report: Document }
	| { kind: 'failed'; error: string };

// runScan performs one scan and always resolves to a terminal state. A thrown
// error, including the engine going away mid-run, becomes a failed state.
export async function runScan(
	scanFn: (path: string, signal?: AbortSignal) => Promise<Document>,
	path: string,
	signal?: AbortSignal
): Promise<RunState> {
	if (path.trim() === '') {
		return { kind: 'failed', error: 'an artifact path is required' };
	}
	try {
		const report = await scanFn(path, signal);
		return { kind: 'done', report };
	} catch (e) {
		return { kind: 'failed', error: e instanceof Error ? e.message : String(e) };
	}
}

// canDownload is true only for a completed run. A failed or running scan offers
// no download, so the UI cannot present a false success.
export function canDownload(state: RunState): boolean {
	return state.kind === 'done';
}
