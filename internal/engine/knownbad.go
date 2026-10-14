package engine

import (
	"strings"
	"time"

	"github.com/defilantech/socair/internal/feed"
)

// KnownBadList is one known-bad hash list a scan matches against: a verified
// feed's denylist, or the local SOCAIR_DENYLIST.
type KnownBadList struct {
	// Source names the list as a scan's Known-bad row does: "feed <issuer>
	// <version>" or "denylist <file name> (sha256 <hex>)", never the
	// list's path on the host.
	Source string
	// Entries maps a known-bad SHA-256 (lowercase hex) to its label.
	Entries map[string]string
}

// KnownBad is the known-bad hash lists a scan started now would read, loaded
// by the same rules: a configured feed that does not verify or has expired
// is an error, and a local list that cannot be read is reported in Unread,
// where a scan leaves its row NOT_TESTED. The airlock's recheck matches clean
// models against it without rescanning them.
type KnownBad struct {
	// Feed is the verified feed when SOCAIR_FEED is set, even one that
	// carries no denylist; nil otherwise.
	Feed *feed.Feed
	// Lists are the lists that were read, the feed's first. Empty when none
	// is configured.
	Lists []KnownBadList
	// Unread is why a configured local list could not be read, or "".
	Unread string
}

// LoadKnownBad reads the known-bad lists a scan would read at now. It loads
// every reference input a scan does, so a configuration a scan refuses is
// refused here too.
func LoadKnownBad(now time.Time) (*KnownBad, error) {
	r, err := loadReferences(now)
	if err != nil {
		return nil, err
	}
	k := &KnownBad{Feed: r.feed, Unread: r.denyErr}
	if f := r.feed; f != nil && len(f.Denylist) > 0 {
		entries := make(map[string]string, len(f.Denylist))
		for h, label := range f.Denylist {
			entries[strings.ToLower(h)] = label
		}
		k.Lists = append(k.Lists, KnownBadList{Source: "feed " + f.Issuer + " " + f.Version, Entries: entries})
	}
	if r.local != nil {
		entries := make(map[string]string, len(r.local))
		for h, e := range r.local {
			entries[strings.ToLower(h)] = e.Label
		}
		k.Lists = append(k.Lists, KnownBadList{Source: "denylist " + r.localName, Entries: entries})
	}
	return k, nil
}

// Match returns every list that names sha, each as "<label> (<source>)".
func (k *KnownBad) Match(sha string) []string {
	sha = strings.ToLower(strings.TrimSpace(sha))
	var out []string
	for _, l := range k.Lists {
		if label, ok := l.Entries[sha]; ok {
			if strings.TrimSpace(label) == "" {
				label = "listed"
			}
			out = append(out, label+" ("+l.Source+")")
		}
	}
	return out
}

// Sources names the lists that were read.
func (k *KnownBad) Sources() []string {
	out := make([]string, 0, len(k.Lists))
	for _, l := range k.Lists {
		out = append(out, l.Source)
	}
	return out
}
