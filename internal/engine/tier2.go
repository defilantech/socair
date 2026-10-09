package engine

import (
	"context"

	"github.com/defilantech/socair/internal/report"
	"github.com/defilantech/socair/internal/tier2"
)

// measureTier2 runs the Tier 2 probe helper, when one is configured, against
// the scan's snapshot and records what it measured (docs/tier2.md). It runs
// before finish, which adds the rows the measurements raise.
//
// A helper that fails, runs out of time, or answers out of protocol leaves
// Tier 2 not run, and the report says why. That is not a gap that withholds
// promotion: Tier 2 can only withhold, so its absence changes no promotion,
// just as an unconfigured helper changes none.
func measureTier2(d *report.Document, cfg *tier2.Config, snapshot string) {
	if cfg == nil {
		return
	}
	sec, err := tier2.Run(context.Background(), cfg, tier2.Artifact{
		Path:     snapshot,
		SHA256:   d.Artifact.SHA256,
		FileName: d.Artifact.FileName,
		Format:   d.Artifact.Format,
	})
	if err != nil {
		d.Tier2DidNotRun("Tier 2 was configured (SOCAIR_TIER2_HELPER) but did not run: " + err.Error())
		return
	}
	d.RecordTier2(sec)
}
