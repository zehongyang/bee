package dbs

import "testing"

type fakeRow struct {
	ID int64
}

// TestBuildCursorResultHasMore 验证查出的记录数超过 limit（即命中了 ApplyCursor 多查的那一条探测记录）时，
// has_more 为 true，且多出来的那一条会被截掉，next_after_id 取截断后最后一条的主键。
func TestBuildCursorResultHasMore(t *testing.T) {
	items := []fakeRow{{ID: 1}, {ID: 2}, {ID: 3}}
	got, result := BuildCursorResult(items, 2, func(r fakeRow) int64 { return r.ID })

	if len(got) != 2 {
		t.Fatalf("expected 2 items after truncation, got %d", len(got))
	}
	if !result.HasMore {
		t.Fatalf("expected HasMore=true when items exceed limit")
	}
	if result.NextAfterID != 2 {
		t.Fatalf("expected NextAfterID=2, got %d", result.NextAfterID)
	}
}

// TestBuildCursorResultNoMore 验证记录数不超过 limit 时，has_more 为 false 且结果不会被截断。
func TestBuildCursorResultNoMore(t *testing.T) {
	items := []fakeRow{{ID: 1}, {ID: 2}}
	got, result := BuildCursorResult(items, 5, func(r fakeRow) int64 { return r.ID })

	if len(got) != 2 {
		t.Fatalf("expected 2 items, got %d", len(got))
	}
	if result.HasMore {
		t.Fatalf("expected HasMore=false when items do not exceed limit")
	}
	if result.NextAfterID != 2 {
		t.Fatalf("expected NextAfterID=2, got %d", result.NextAfterID)
	}
}

// TestBuildCursorResultEmpty 验证空结果时不会 panic，且 next_after_id 保持零值。
func TestBuildCursorResultEmpty(t *testing.T) {
	got, result := BuildCursorResult([]fakeRow{}, 10, func(r fakeRow) int64 { return r.ID })

	if len(got) != 0 {
		t.Fatalf("expected 0 items, got %d", len(got))
	}
	if result.HasMore || result.NextAfterID != 0 {
		t.Fatalf("expected zero-value result for empty input, got %+v", result)
	}
}

// TestNormalizeLimit 验证非法 limit 会被归一化到默认值或最大值区间内。
func TestNormalizeLimit(t *testing.T) {
	cases := []struct {
		in   int
		want int
	}{
		{in: 0, want: DefaultPageSize},
		{in: -5, want: DefaultPageSize},
		{in: 10, want: 10},
		{in: MaxPageSize + 1, want: MaxPageSize},
	}
	for _, c := range cases {
		if got := normalizeLimit(c.in); got != c.want {
			t.Fatalf("normalizeLimit(%d) = %d, want %d", c.in, got, c.want)
		}
	}
}
