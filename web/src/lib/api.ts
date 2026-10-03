// The typed client for the Socair engine API.
//
// The wizard shows only state the engine returned. It derives no status, count,
// or badge of its own, and it treats every non-2xx as a failure rather than a
// partial success.

// CHECK_STATUSES is the status enum of the report contract. A test holds it
// to docs/report-schema/v1.json, so the wizard cannot drift from the engine.
export const CHECK_STATUSES = ['PASS', 'FAIL', 'LEAD', 'NOT_TESTED'] as const;
export type CheckStatus = (typeof CHECK_STATUSES)[number];

export interface CheckResult {
	name: string;
	looks_for: string;
	status: CheckStatus;
	evidence?: string;
	notes?: string;
}

export interface PromotionAuthorization {
	authorized: boolean;
	state: string;
	level?: string;
	conditions?: string;
	accepted_surfaces?: string[];
	accepted_by?: string;
}

export interface Artifact {
	name: string;
	file_name: string;
	sha256: string;
	format: string;
	size_bytes: number;
	architecture?: string;
	split?: string;
	quant_declared?: string;
}

export interface Document {
	schema_version: string;
	artifact: Artifact;
	checks: CheckResult[];
	findings: { fails: string[]; leads?: string[]; not_tested: string[] };
	promotion_authorization: PromotionAuthorization;
	bounded_statement: string;
	out_of_scope: { does_not_certify: string; ceiling: string[] };
	verification: { artifact_sha256: string };
}

export interface Health {
	ok: boolean;
	store: string;
	version: string;
	error?: string;
}

export interface AirlockEvent {
	ts: string;
	action: string;
	outcome: string;
	source?: string;
	repo?: string;
	sha256?: string;
	detail?: string;
}

// ApiError is a non-2xx from the engine, carrying the engine's own message.
export class ApiError extends Error {
	status: number;
	constructor(status: number, message: string) {
		super(message);
		this.name = 'ApiError';
		this.status = status;
	}
}

async function decodeError(resp: Response): Promise<never> {
	let message = `engine returned HTTP ${resp.status}`;
	const text = await resp.text().catch(() => '');
	try {
		const body = JSON.parse(text) as { error?: string };
		if (body.error) message = body.error;
	} catch {
		// Not JSON; keep the status-based message.
	}
	throw new ApiError(resp.status, message);
}

export async function scan(path: string, signal?: AbortSignal): Promise<Document> {
	const resp = await fetch('/api/scan', {
		method: 'POST',
		headers: { 'content-type': 'application/json' },
		body: JSON.stringify({ path }),
		signal
	});
	if (!resp.ok) await decodeError(resp);
	const out = (await resp.json()) as { report?: Document };
	if (!out.report) throw new ApiError(500, 'engine returned no report');
	return out.report;
}

export async function renderReport(
	report: Document,
	format: 'html' | 'pdf' | 'sarif'
): Promise<Blob> {
	const resp = await fetch('/api/render', {
		method: 'POST',
		headers: { 'content-type': 'application/json' },
		body: JSON.stringify({ report, format })
	});
	if (!resp.ok) await decodeError(resp);
	return await resp.blob();
}

export async function health(signal?: AbortSignal): Promise<Health> {
	const resp = await fetch('/api/health', { signal });
	if (!resp.ok) await decodeError(resp);
	return (await resp.json()) as Health;
}

export async function airlockLog(signal?: AbortSignal): Promise<AirlockEvent[]> {
	const resp = await fetch('/api/airlock/log', { signal });
	if (!resp.ok) await decodeError(resp);
	const out = (await resp.json()) as { events?: AirlockEvent[] };
	return out.events ?? [];
}

// downloadReport triggers a browser download of the rendered report.
export async function downloadReport(
	report: Document,
	format: 'html' | 'pdf',
	filename: string
): Promise<void> {
	const blob = await renderReport(report, format);
	const url = URL.createObjectURL(blob);
	const a = document.createElement('a');
	a.href = url;
	a.download = filename;
	a.click();
	URL.revokeObjectURL(url);
}
