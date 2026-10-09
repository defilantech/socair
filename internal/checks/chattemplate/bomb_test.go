package chattemplate

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

// TestFoldingIsBounded: constant folding through set chains doubles a string
// per line, so forty lines would build a terabyte, and a replace chain grows
// eightfold per line. Folding stops at a size cap and the check finishes
// promptly. Falsification: drop the cap and this runs out of memory or time.
func TestFoldingIsBounded(t *testing.T) {
	var b strings.Builder
	b.WriteString("{% set v0 = 'ab' %}")
	for i := 1; i <= 40; i++ {
		fmt.Fprintf(&b, "{%% set v%d = v%d ~ v%d %%}", i, i-1, i-1)
	}
	b.WriteString("{{ v40 }}")
	b.WriteString("{% set r = 'a' %}")
	for i := 0; i < 40; i++ {
		b.WriteString("{% set r = r|replace('a', 'aaaaaaaa') %}")
	}
	start := time.Now()
	_ = Inspect(b.String())
	// Uncapped, this does not finish; capped, it takes well under a second,
	// and two to three under the race detector on CI's shared runners. The
	// bound only has to tell the two apart.
	if el := time.Since(start); el > 15*time.Second {
		t.Fatalf("a folding bomb took %s", el)
	}
}
