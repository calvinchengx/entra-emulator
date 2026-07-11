package clock

import "testing"

// fixedClock returns a clock whose "real" time is pinned, so offset/freeze
// behavior is fully deterministic.
func fixedClock(real int64) *Clock {
	return &Clock{realNow: func() int64 { return real }}
}

func TestOffsetAndAdvance(t *testing.T) {
	c := fixedClock(1000)
	if c.Now() != 1000 {
		t.Fatalf("baseline: %d", c.Now())
	}
	c.SetOffset(500)
	if c.Now() != 1500 {
		t.Fatalf("after SetOffset(500): %d", c.Now())
	}
	c.Advance(250)
	if c.Now() != 1750 {
		t.Fatalf("after Advance(250): %d", c.Now())
	}
	c.Advance(-750)
	if c.Now() != 1000 {
		t.Fatalf("after Advance(-750): %d", c.Now())
	}
}

func TestFreezeHoldsTime(t *testing.T) {
	c := fixedClock(2000)
	c.SetOffset(100) // Now = 2100
	c.Freeze()
	if c.Now() != 2100 {
		t.Fatalf("frozen now: %d", c.Now())
	}
	// Advancing real time (simulate) must not move a frozen clock.
	c.realNow = func() int64 { return 9999 }
	if c.Now() != 2100 {
		t.Fatalf("frozen clock moved with real time: %d", c.Now())
	}
	// Advance while frozen shifts the frozen value.
	c.Advance(50)
	if c.Now() != 2150 {
		t.Fatalf("advance while frozen: %d", c.Now())
	}
}

func TestUnfreezeIsContinuous(t *testing.T) {
	c := fixedClock(3000)
	c.Freeze() // frozen at 3000
	c.Advance(500)
	if c.Now() != 3500 {
		t.Fatalf("frozen advanced: %d", c.Now())
	}
	c.Unfreeze() // real time is still 3000; Now must stay 3500
	if c.Now() != 3500 {
		t.Fatalf("unfreeze should be continuous: %d", c.Now())
	}
	if c.State().Frozen {
		t.Fatal("should be unfrozen")
	}
}

func TestReset(t *testing.T) {
	c := fixedClock(4000)
	c.SetOffset(1000)
	c.Freeze()
	c.Reset()
	if c.Now() != 4000 || c.State().OffsetSeconds != 0 || c.State().Frozen {
		t.Fatalf("reset state: %+v now=%d", c.State(), c.Now())
	}
}
