import type { Model } from './api';

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

export function stageLabel(m: Model): string {
	switch (m.stage) {
		case 'approved':
			if (m.promotion_state === 'authorized_with_conditions') {
				const until = m.acceptance_expires ? ` until ${m.acceptance_expires}` : '';
				return `approved with conditions${until}${m.expires_soon ? ' (expires soon)' : ''}`;
			}
			return 'approved';
		case 'does-not-verify':
			return 'does not verify';
		case 'acceptance-expired':
			return 'acceptance expired';
		case 'needs-acceptance':
			return 'needs acceptance';
		case 'ready':
			return 'ready to promote';
		default:
			return m.stage;
	}
}

export function isApprovedList(m: Model): boolean {
	return (
		m.location === 'clean' &&
		(m.stage === 'approved' || m.stage === 'acceptance-expired' || m.stage === 'does-not-verify')
	);
}
