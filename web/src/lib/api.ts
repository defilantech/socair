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
	/** Fixed statement of what this check's PASS establishes, and where it stops. */
	pass_means?: string;
	/** Triage grade of a FAIL or LEAD row; absent otherwise. Does not change promotion. */
	severity?: 'critical' | 'high' | 'medium' | 'low';
	/** External framework entries the check addresses. */
	maps_to?: { framework: string; id: string; name: string }[];
}

export interface PromotionAuthorization {
	authorized: boolean;
	state: string;
	level?: string;
	conditions?: string;
	accepted_surfaces?: string[];
	accepted_by?: string;
	/** The acceptor's signed acceptance (base64 DSSE envelope); absent means unsigned. */
	acceptance?: string;
	reviewed_document_hash?: string;
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
	files?: ArtifactFile[];
	/** The license the artifact states. Identity, not a check. */
	license?: License;
	/** The base models the artifact declares; claims, not verified lineage. */
	base_models?: BaseModel[];
}

/**
 * The license the artifact states: id and name when its statements name one
 * license, disagreement (and no id) when they name more, neither when none
 * was identified.
 */
export interface License {
	id?: string;
	name?: string;
	sources?: LicenseSource[];
	disagreement?: string;
}

/** One statement of the license, and where it was read. */
export interface LicenseSource {
	source: string;
	value: string;
	/** The license it names; absent when it names none. */
	id?: string;
	note?: string;
}

export interface BaseModel {
	name: string;
	organization?: string;
	repo?: string;
	url?: string;
	source: string;
}

/** One file of a model directory; artifact.sha256 is the digest of their manifest. */
export interface ArtifactFile {
	path: string;
	sha256: string;
	size_bytes: number;
	role: 'weights' | 'config' | 'tokenizer' | 'chat_template' | 'code' | 'adapter' | 'other';
}

/** Section 3 of the attestation: how and against what the checks ran. */
export interface Scope {
	check_set_version: string;
	tool_versions?: string;
	execution_context: string;
	input_path: string;
	scan_start_utc?: string;
	scan_end_utc?: string;
	inference_budget?: string;
	reference_data?: string;
}

// MEASUREMENT_OUTCOMES is the Tier 2 outcome enum of the report contract. A
// test holds it to docs/report-schema/v1.json. There is no pass: "measured"
// means the measurement completed and raised nothing.
export const MEASUREMENT_OUTCOMES = ['measured', 'lead', 'fail', 'error'] as const;
export type MeasurementOutcome = (typeof MEASUREMENT_OUTCOMES)[number];

/** How the model was sampled for a measurement. */
export interface Decoding {
	temperature: number;
	top_p: number;
	max_tokens: number;
	seed?: number;
}

/** One Tier 2 measurement: what ran, how it was scored, where, and what came out. */
export interface Measurement {
	/** The Tier 2 check measured; ends in " (Tier 2)". */
	check: string;
	suite: string;
	suite_version: string;
	dataset_digest: string;
	/** "deterministic" or "llm-judge:sha256:<hex>". */
	scorer: string;
	n: number;
	score?: number;
	metrics?: Record<string, number>;
	/** 95% confidence interval of the score, [low, high]. */
	ci95?: number[];
	decoding: Decoding;
	engine: string;
	/** Hash of the node class it ran on (one of tier2.node_classes). */
	node_class: string;
	reference_node_class?: string;
	started_utc: string;
	ended_utc: string;
	outcome: MeasurementOutcome;
	evidence?: string;
	notes?: string;
}

/** What decides a model's numerics on a node; unreported text is "", counts 0, switches null. */
export interface NodeClass {
	schema: string;
	gpu_model: string;
	compute_capability: string;
	gpu_count: number;
	interconnect: string;
	driver: string;
	vbios: string;
	ecc: boolean | null;
	mig: string;
	cc_mode: string;
	cuda: string;
	cublas: string;
	cudnn: string;
	nccl: string;
	container_image_digest: string;
	engine_name: string;
	engine_version: string;
	engine_commit: string;
	dtype: string;
	weight_quantization: string;
	kv_cache_quantization: string;
	tensor_parallel_size: number;
	pipeline_parallel_size: number;
	expert_parallel_size: number;
	attention_backend: string;
	cuda_graphs: boolean | null;
	torch_compile: boolean | null;
	eager: boolean | null;
	batch_invariant: boolean | null;
	prefix_caching: boolean | null;
	chunked_prefill: boolean | null;
	speculative_decoding: string;
	env: Record<string, string> | null;
}

export interface NodeClassRecord {
	/** sha256 over the canonical JSON of facts. */
	hash: string;
	/** Who stated the facts; Socair does not observe the hardware. */
	reported_by: string;
	facts: NodeClass;
}

/** Measurements made by running the model. Absent when Tier 2 did not run. */
export interface Tier2 {
	statement: string;
	helper: string;
	node_classes: NodeClassRecord[];
	measurements: Measurement[];
}

export interface Document {
	schema_version: string;
	artifact: Artifact;
	/** Always sent by the engine; optional here so hand-built fixtures stay small. */
	scope?: Scope;
	checks: CheckResult[];
	/** Tier 2 measurements; present only when Tier 2 ran. */
	tier2?: Tier2;
	findings: { fails: string[]; leads?: string[]; not_tested: string[] };
	promotion_authorization: PromotionAuthorization;
	bounded_statement: string;
	out_of_scope: {
		does_not_certify: string;
		ceiling: string[];
		unparsed_formats?: string[];
		untested_node_classes?: string[];
		not_run?: { name: string; looks_for: string; reason: string }[];
	};
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
	actor?: string;
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

export type Stage =
	| 'staged'
	| 'scanned'
	| 'ready'
	| 'needs-acceptance'
	| 'blocked'
	| 'approved'
	| 'acceptance-expired'
	| 'does-not-verify';

export interface Model {
	id: string;
	name: string;
	format?: string;
	size_bytes?: number;
	location: 'staging' | 'clean';
	stage: Stage;
	stage_reason?: string;
	promotion_state?: string;
	issuer?: string;
	signer_key_id?: string;
	accepted_surfaces?: string[];
	accepted_by?: string;
	acceptance_expires?: string;
	expires_soon?: boolean;
	promoted_at?: string;
	next: { action: 'scan' | 'sign' | 'accept' | 'promote' | 'none'; command?: string };
}

export async function models(signal?: AbortSignal): Promise<Model[]> {
	const resp = await fetch('/api/airlock/models', { signal });
	if (!resp.ok) await decodeError(resp);
	return ((await resp.json()) as { models?: Model[] }).models ?? [];
}

export async function model(
	id: string,
	signal?: AbortSignal
): Promise<{
	model: Model;
	report: Document | null;
	events: AirlockEvent[];
	/** Evidence files this entry holds (names the files route serves). */
	evidence: string[];
}> {
	const resp = await fetch(`/api/airlock/models/${encodeURIComponent(id)}`, { signal });
	if (!resp.ok) await decodeError(resp);
	return await resp.json();
}

export async function scanStaged(id: string): Promise<Model> {
	const resp = await fetch(`/api/airlock/models/${encodeURIComponent(id)}/scan`, {
		method: 'POST',
		headers: { 'content-type': 'application/json' },
		body: '{}'
	});
	if (!resp.ok) await decodeError(resp);
	return ((await resp.json()) as { model: Model }).model;
}

// uploadAttestation sends a signed envelope unchanged: its signature covers
// the exact bytes.
export async function uploadAttestation(id: string, envelope: string): Promise<Model> {
	const resp = await fetch(`/api/airlock/models/${encodeURIComponent(id)}/attestation`, {
		method: 'POST',
		headers: { 'content-type': 'application/json' },
		body: envelope
	});
	if (!resp.ok) await decodeError(resp);
	return ((await resp.json()) as { model: Model }).model;
}

export async function exportSnapshot(): Promise<Blob> {
	const resp = await fetch('/api/airlock/export', {
		method: 'POST',
		headers: { 'content-type': 'application/json' },
		body: '{}'
	});
	if (!resp.ok) await decodeError(resp);
	return await resp.blob();
}

export function evidenceURL(id: string, name: string): string {
	return `/api/airlock/models/${encodeURIComponent(id)}/files/${encodeURIComponent(name)}`;
}
