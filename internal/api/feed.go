package api

import (
	"net/http"
	"strings"
	"time"

	"github.com/defilantech/socair/internal/engine"
	"github.com/defilantech/socair/internal/feed"
)

// FeedStatus is what GET /api/feed reports about the configured feed: what a
// scan started now would make of it. It reads and writes nothing in the
// store, and it never changes a scan.
type FeedStatus struct {
	// Configured is true when SOCAIR_FEED names a feed.
	Configured bool `json:"configured"`
	// Feed names the feed, when it verifies.
	Feed *feed.Record `json:"feed,omitempty"`
	// ExpiresSoon is true in the last third of the feed's validity, and
	// Notice then says when it expires and that scans will then stop.
	ExpiresSoon bool   `json:"expires_soon,omitempty"`
	Notice      string `json:"notice,omitempty"`
	// StoreRecord is the newest feed the configured store has used.
	StoreRecord *feed.Record `json:"store_record,omitempty"`
	// Error is why a scan with this configuration would stop: the feed does
	// not verify or has expired, or the store would refuse it.
	Error string `json:"error,omitempty"`
}

// feedStatus answers GET /api/feed. A feed that does not verify is reported
// in the body, not as a failed request: the route's question is the feed's
// state, and the console shows it.
func (o Options) feedStatus(w http.ResponseWriter, _ *http.Request) {
	at := time.Now()
	var st FeedStatus
	f, err := engine.LoadFeed(at)
	switch {
	case err != nil:
		st.Configured, st.Error = true, "scans stop: "+err.Error()
	case f != nil:
		st.Configured = true
		rec := f.Record()
		st.Feed = &rec
		st.Notice = f.ExpiryNotice(at)
		st.ExpiresSoon = st.Notice != ""
		if strings.TrimSpace(o.StoreRoot) != "" {
			if s, err := o.store(); err != nil {
				st.Error = "the feed cannot be checked against the store's record: " + err.Error()
			} else {
				st.StoreRecord, err = s.ReviewFeed(f)
				if err != nil {
					st.Error = err.Error()
				}
			}
		}
	}
	writeJSON(w, http.StatusOK, st)
}
