// Date display for the console. Presentational only: the engine's timestamp
// is kept whole in the <time datetime> and title, and nothing here decides a
// state (expiry flags come from the engine's expires_soon).

const MONTHS = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
const DAY = 24 * 60 * 60 * 1000;

function parse(iso: string | undefined): Date | null {
	if (!iso) return null;
	const d = new Date(iso);
	return Number.isNaN(d.getTime()) ? null : d;
}

// shortDate renders an ISO timestamp as "22 Oct 2026" (UTC, so the same
// page reads the same on every host). An unparseable value is returned as is.
export function shortDate(iso: string | undefined): string {
	const d = parse(iso);
	if (!d) return iso ?? '';
	return `${d.getUTCDate()} ${MONTHS[d.getUTCMonth()]} ${d.getUTCFullYear()}`;
}

// shortTime renders "22 Oct 2026, 14:05 UTC" for log lines.
export function shortTime(iso: string | undefined): string {
	const d = parse(iso);
	if (!d) return iso ?? '';
	const hh = String(d.getUTCHours()).padStart(2, '0');
	const mm = String(d.getUTCMinutes()).padStart(2, '0');
	return `${shortDate(iso)}, ${hh}:${mm} UTC`;
}

// relative renders the distance from now in whole days: "in 18 days",
// "4 days ago", "today". It is for reading, not for deciding.
export function relative(iso: string | undefined, now: Date = new Date()): string {
	const d = parse(iso);
	if (!d) return '';
	const days = Math.round((d.getTime() - now.getTime()) / DAY);
	if (days === 0) return 'today';
	if (days === 1) return 'tomorrow';
	if (days === -1) return 'yesterday';
	return days > 0 ? `in ${days} days` : `${-days} days ago`;
}
