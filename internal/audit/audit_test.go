package audit

import "testing"

func TestRecorderNewestFirst(t *testing.T) {
	r := New(10)
	for i := 1; i <= 3; i++ {
		r.Record(Event{Time: int64(i), ClientID: string(rune('a' + i - 1))})
	}
	got := r.List(0)
	if len(got) != 3 {
		t.Fatalf("want 3, got %d", len(got))
	}
	if got[0].Time != 3 || got[2].Time != 1 {
		t.Fatalf("expected newest-first ordering: %+v", got)
	}
	if got[0].TimeISO == "" {
		t.Fatal("Record should stamp TimeISO")
	}
}

func TestRecorderLimit(t *testing.T) {
	r := New(10)
	for i := 0; i < 5; i++ {
		r.Record(Event{Time: int64(i)})
	}
	if n := len(r.List(2)); n != 2 {
		t.Fatalf("limit 2 should return 2, got %d", n)
	}
}

func TestRecorderRingWraparound(t *testing.T) {
	r := New(3) // capacity 3
	for i := 1; i <= 5; i++ {
		r.Record(Event{Time: int64(i)})
	}
	got := r.List(0)
	if len(got) != 3 {
		t.Fatalf("ring should hold only 3, got %d", len(got))
	}
	// Newest 3 are 5,4,3.
	if got[0].Time != 5 || got[1].Time != 4 || got[2].Time != 3 {
		t.Fatalf("wraparound kept wrong events: %+v", got)
	}
}

func TestRecorderClear(t *testing.T) {
	r := New(3)
	r.Record(Event{Time: 1})
	r.Clear()
	if n := len(r.List(0)); n != 0 {
		t.Fatalf("clear should empty, got %d", n)
	}
}
