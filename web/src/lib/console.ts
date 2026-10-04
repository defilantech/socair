import type { AirlockEvent, Model, Stage } from './api';

export type Tone = 'ok' | 'amber' | 'red' | 'neutral';

// stageTone maps the engine's stage to a colour. Only an unconditional
// authorization is green; conditions are amber; anything that does not
// verify, has lapsed, or is blocked is red.
export function stageTone(m: Model): Tone {
	switch (m.stage) {
		case 'approved':
			return m.promotion_state === 'authorized' ? 'ok' : 'amber';
		case 'does-not-verify':
		case 'acceptance-expired':
		case 'blocked':
			return 'red';
		case 'needs-acceptance':
			return 'amber';
		default:
			return 'neutral';
	}
}

// stageLabel is the words for the engine's stage of one model. The expiry
// date is shown beside it (see when.ts), not inside it.
export function stageLabel(m: Model): string {
	if (m.stage === 'approved' && m.promotion_state === 'authorized_with_conditions') {
		return `approved with conditions${m.expires_soon ? ' (expires soon)' : ''}`;
	}
	return stageName(m.stage);
}

// stageName is the human name of a stage key, for headings that group models
// by the engine's stage.
export function stageName(stage: Stage | string): string {
	switch (stage) {
		case 'staged':
			return 'staged';
		case 'scanned':
			return 'scanned';
		case 'ready':
			return 'ready to promote';
		case 'needs-acceptance':
			return 'needs acceptance';
		case 'blocked':
			return 'blocked';
		case 'approved':
			return 'approved';
		case 'does-not-verify':
			return 'does not verify';
		case 'acceptance-expired':
			return 'acceptance expired';
		default:
			return stage;
	}
}

// pendingHeading is the Pending group heading for an engine stage, in
// sentence case. It names what the group is waiting for.
export function pendingHeading(stage: Stage | string): string {
	switch (stage) {
		case 'ready':
			return 'Ready to promote';
		case 'needs-acceptance':
			return 'Needs a signed acceptance';
		case 'scanned':
			return 'Scanned, waiting for a signature';
		case 'staged':
			return 'Staged, not scanned';
		case 'blocked':
			return 'Blocked';
		case 'acceptance-expired':
			return 'Acceptance expired';
		case 'does-not-verify':
			return 'Does not verify';
		default:
			return stage;
	}
}

// reasonBeyondLabel returns the engine's stage reason only where it adds to
// the label: a reason that is the label, or opens with "<label>: ", loses
// that prefix. Presentational only; the engine's reason is not changed.
export function reasonBeyondLabel(m: Model): string {
	const reason = (m.stage_reason ?? '').trim();
	if (!reason) return '';
	const label = stageName(m.stage).toLowerCase();
	const lower = reason.toLowerCase();
	if (lower === label) return '';
	if (lower.startsWith(label + ':')) return reason.slice(label.length + 1).trim();
	return reason;
}

export function isApprovedList(m: Model): boolean {
	return (
		m.location === 'clean' &&
		(m.stage === 'approved' || m.stage === 'acceptance-expired' || m.stage === 'does-not-verify')
	);
}

export interface Section {
	key: 'not-valid' | 'conditions' | 'approved';
	heading: string;
	models: Model[];
}

// approvedSections groups the clean store by the engine's stage: what is not
// currently valid first (it needs action), then conditional approvals by
// soonest expiry, then unconditional approvals. Empty sections are omitted.
export function approvedSections(list: Model[]): Section[] {
	const clean = list.filter(isApprovedList);
	const notValid = clean.filter((m) => m.stage === 'acceptance-expired' || m.stage === 'does-not-verify');
	// Anything approved without an unconditional authorization sits with the
	// conditions, so nothing is hidden and nothing unconditional is claimed.
	const conditions = clean
		.filter((m) => m.stage === 'approved' && m.promotion_state !== 'authorized')
		.sort((a, b) => (a.acceptance_expires ?? '￿').localeCompare(b.acceptance_expires ?? '￿'));
	const approved = clean.filter((m) => m.stage === 'approved' && m.promotion_state === 'authorized');
	const out: Section[] = [
		{ key: 'not-valid', heading: 'Not currently valid', models: notValid },
		{ key: 'conditions', heading: 'Approved with conditions', models: conditions },
		{ key: 'approved', heading: 'Approved', models: approved }
	];
	return out.filter((s) => s.models.length > 0);
}

// acceptedLine is the count line over a model's accepted gaps, from the
// engine's list. Each surface is shown as its own item: a check name can
// contain commas ("Hash, provenance, lineage"), so the list is never joined.
export function acceptedLine(surfaces: string[] | undefined): string {
	const n = surfaces?.length ?? 0;
	return n === 1 ? '1 accepted gap' : `${n} accepted gaps`;
}

// nextPurpose is the one-line purpose shown above a command the engine
// returned, keyed by the engine's next action.
export function nextPurpose(action: Model['next']['action']): string {
	switch (action) {
		case 'scan':
			return 'Scans the staged copy and writes its report';
		case 'sign':
			return 'Signs the report with your operator key';
		case 'accept':
			return 'Records a signed acceptance of the named gaps, with the acceptor key';
		case 'promote':
			return 'Promotes it into the clean store';
		default:
			return '';
	}
}

// eventTone maps a log outcome to a tone: a refusal is red, a conditional
// promotion amber, anything else neutral. Never green: a log line records
// what happened, it does not approve.
export function eventTone(e: AirlockEvent): Tone {
	if (e.outcome === 'refused' || e.action === 'refuse') return 'red';
	if (e.outcome === 'conditional') return 'amber';
	return 'neutral';
}
