package feed

import (
	"fmt"
	"time"
)

// A feed past its expiry stops every scan that uses it, by design: stale
// reference data must not change verdicts quietly. So that a site is not
// surprised by it, Socair warns while a feed is in the last third of its
// validity window, from issued to expires. A fraction, not a fixed number of
// days, scales with the issuer's cadence: a 90-day feed released monthly warns
// 30 days ahead, once two releases have been missed, and a 7-day feed warns
// about 2 days ahead instead of always.
//
// The warning is information for the operator. It never changes a check row,
// a verdict, or a report.

// warnDivisor sets the warning window: the last 1/warnDivisor of a feed's
// validity.
const warnDivisor = 3

// ExpiresSoon reports whether, at now, the feed is in the last third of its
// validity window, or past its expiry. A feed whose times do not parse is not
// reported: Load refuses it.
func (i Info) ExpiresSoon(now time.Time) bool {
	issued, err1 := time.Parse(time.RFC3339, i.Issued)
	expires, err2 := time.Parse(time.RFC3339, i.Expires)
	if err1 != nil || err2 != nil || !expires.After(issued) {
		return false
	}
	return warnDivisor*expires.Sub(now) <= expires.Sub(issued)
}

// ExpiryNotice is the warning for a feed that ExpiresSoon: when it expires,
// and that every scan using it then stops. It is "" for any other feed.
func (i Info) ExpiryNotice(now time.Time) string {
	if !i.ExpiresSoon(now) {
		return ""
	}
	expires, _ := time.Parse(time.RFC3339, i.Expires)
	left := expires.Sub(now)
	if left <= 0 {
		return fmt.Sprintf("feed %s %s expired at %s: every scan and recheck that uses it stops until a newer feed is imported",
			i.Issuer, i.Version, i.Expires)
	}
	return fmt.Sprintf("feed %s %s expires at %s, %s: after that, every scan and recheck that uses it stops. Import a newer feed before then",
		i.Issuer, i.Version, i.Expires, until(left))
}

// until says how far off a positive duration is, rounded down.
func until(d time.Duration) string {
	const day = 24 * time.Hour
	switch {
	case d >= 2*day:
		return fmt.Sprintf("in %d days", int(d/day))
	case d >= 2*time.Hour:
		return fmt.Sprintf("in %d hours", int(d/time.Hour))
	default:
		return "in less than two hours"
	}
}
