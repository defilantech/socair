package feed

import (
	"errors"
	"fmt"
	"strings"
	"time"
)

// A site that has used a feed must not be moved back to an older one that is
// still inside its validity window: an older feed can undo a newer one's
// denylist entries and reviews (a rollback attack, in TUF's terms). The
// order between two feeds is their signed issue time. A feed's version is a
// free-form label with no defined order, so it names a feed but does not
// order it.
//
// Where the newest feed a site has used is remembered is the caller's
// business: internal/airlock keeps it in the store. This file only names a
// feed exactly and orders two of them.

// Record names one feed exactly, as a site remembers it: who issued it, its
// version and validity, the key that signed it, and the SHA-256 of its signed
// statement.
type Record struct {
	Issuer  string `json:"issuer"`
	Version string `json:"version"`
	Issued  string `json:"issued"`
	Expires string `json:"expires"`
	KeyID   string `json:"key_id"`
	// Statement is the SHA-256 of the feed's signed statement.
	Statement string `json:"statement_sha256"`
}

// Record names the feed.
func (f *Feed) Record() Record {
	return Record{Issuer: f.Issuer, Version: f.Version, Issued: f.Issued, Expires: f.Expires, KeyID: f.KeyID, Statement: f.StatementSHA256}
}

// String names the feed for a message or a log entry.
func (r Record) String() string {
	return fmt.Sprintf("feed %s %s, issued %s, expires %s, signed by key %s, statement sha256 %s",
		r.Issuer, r.Version, r.Issued, r.Expires, shortID(r.KeyID), shortID(r.Statement))
}

// short names the feed in a sentence that already gives its role.
func (r Record) short() string {
	return fmt.Sprintf("feed %s %s (issued %s)", r.Issuer, r.Version, r.Issued)
}

// ErrRollback is wrapped by every error that refuses a feed for being older
// than the newest one a site has used.
var ErrRollback = errors.New("feed rollback")

// Newer reports whether candidate may replace recorded, the newest feed a
// site has used. It is true for a feed issued later, false with no error for
// the recorded feed itself (the same signed statement), and an error wrapping
// ErrRollback for anything else: a feed issued earlier, or a different feed
// issued at the same time, which cannot be ordered. A record whose issue time
// does not parse is an error too.
//
// The comparison is over every issuer and key: a feed signed by another
// trusted key, or naming another issuer, is held to the same order, so a
// second trusted key cannot be used to bring back an older feed.
func Newer(recorded, candidate Record) (bool, error) {
	if recorded.Statement != "" && strings.EqualFold(recorded.Statement, candidate.Statement) {
		return false, nil
	}
	was, err := time.Parse(time.RFC3339, recorded.Issued)
	if err != nil {
		return false, fmt.Errorf("the recorded feed's issue time %q is not RFC 3339", recorded.Issued)
	}
	now, err := time.Parse(time.RFC3339, candidate.Issued)
	if err != nil {
		return false, fmt.Errorf("feed %s %s: issue time %q is not RFC 3339", candidate.Issuer, candidate.Version, candidate.Issued)
	}
	switch {
	case now.After(was):
		return true, nil
	case now.Equal(was):
		return false, fmt.Errorf("%w: %s is a different feed from %s, the newest feed used here, and was issued at the same time, so the two cannot be ordered",
			ErrRollback, candidate.short(), recorded.short())
	default:
		return false, fmt.Errorf("%w: %s is older than %s, the newest feed used here", ErrRollback, candidate.short(), recorded.short())
	}
}
