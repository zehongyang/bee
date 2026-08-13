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

// TestBuildCursorResultDesc 验证降序查询同样能用 BuildCursorResult：
// 截断后最后一条是本页最小的 ID，正是下一页 "id < afterID" 该用的游标。
func TestBuildCursorResultDesc(t *testing.T) {
	items := []fakeRow{{ID: 9}, {ID: 8}, {ID: 7}}
	got, result := BuildCursorResult(items, 2, func(r fakeRow) int64 { return r.ID })

	if len(got) != 2 || got[0].ID != 9 || got[1].ID != 8 {
		t.Fatalf("expected items [9 8], got %+v", got)
	}
	if !result.HasMore {
		t.Fatalf("expected HasMore=true when items exceed limit")
	}
	if result.NextAfterID != 8 {
		t.Fatalf("expected NextAfterID=8, got %d", result.NextAfterID)
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

// TestOffsetPageNormalize 验证页码和每页条数的归一化：页码非法退回第 1 页，
// 每页条数复用游标分页那套 DefaultPageSize / MaxPageSize 约束。
func TestOffsetPageNormalize(t *testing.T) {
	cases := []struct {
		in           OffsetPage
		wantPage     int
		wantPageSize int
	}{
		{in: OffsetPage{Page: 0, PageSize: 0}, wantPage: 1, wantPageSize: DefaultPageSize},
		{in: OffsetPage{Page: -3, PageSize: -1}, wantPage: 1, wantPageSize: DefaultPageSize},
		{in: OffsetPage{Page: 4, PageSize: 15}, wantPage: 4, wantPageSize: 15},
		{in: OffsetPage{Page: 2, PageSize: MaxPageSize + 100}, wantPage: 2, wantPageSize: MaxPageSize},
	}
	for _, c := range cases {
		got := c.in.Normalize()
		if got.Page != c.wantPage || got.PageSize != c.wantPageSize {
			t.Fatalf("OffsetPage%+v.Normalize() = %+v, want page=%d size=%d",
				c.in, got, c.wantPage, c.wantPageSize)
		}
	}
}

// TestOffsetPageOffset 验证起始偏移量按归一化后的页码计算，非法页码不会算出负偏移。
func TestOffsetPageOffset(t *testing.T) {
	cases := []struct {
		in   OffsetPage
		want int
	}{
		{in: OffsetPage{Page: 1, PageSize: 20}, want: 0},
		{in: OffsetPage{Page: 3, PageSize: 20}, want: 40},
		{in: OffsetPage{Page: 0, PageSize: 10}, want: 0},
		{in: OffsetPage{Page: -5, PageSize: 10}, want: 0},
	}
	for _, c := range cases {
		if got := c.in.Offset(); got != c.want {
			t.Fatalf("OffsetPage%+v.Offset() = %d, want %d", c.in, got, c.want)
		}
	}
}

// TestBuildOffsetResult 验证总页数向上取整，且总条数为 0 时总页数也是 0，
// 前端据此渲染空列表而不是"第 1 页 / 共 1 页"。
func TestBuildOffsetResult(t *testing.T) {
	cases := []struct {
		page      OffsetPage
		total     int64
		wantTotal int
	}{
		{page: OffsetPage{Page: 1, PageSize: 20}, total: 0, wantTotal: 0},
		{page: OffsetPage{Page: 1, PageSize: 20}, total: 1, wantTotal: 1},
		{page: OffsetPage{Page: 1, PageSize: 20}, total: 20, wantTotal: 1},
		{page: OffsetPage{Page: 1, PageSize: 20}, total: 21, wantTotal: 2},
		{page: OffsetPage{Page: 2, PageSize: 15}, total: 100, wantTotal: 7},
	}
	for _, c := range cases {
		got := BuildOffsetResult(c.page, c.total)
		if got.TotalPage != c.wantTotal {
			t.Fatalf("BuildOffsetResult(%+v, %d).TotalPage = %d, want %d",
				c.page, c.total, got.TotalPage, c.wantTotal)
		}
		if got.Total != c.total {
			t.Fatalf("BuildOffsetResult(%+v, %d).Total = %d, want %d",
				c.page, c.total, got.Total, c.total)
		}
	}
}

// TestBuildOffsetResultNormalizes 验证元信息里回显的是归一化之后的页码和每页条数，
// 而不是调用方原样传进来的非法值——前端分页组件要靠这两个值回显当前状态。
func TestBuildOffsetResultNormalizes(t *testing.T) {
	got := BuildOffsetResult(OffsetPage{Page: 0, PageSize: MaxPageSize + 1}, 10)
	if got.Page != 1 {
		t.Fatalf("expected normalized Page=1, got %d", got.Page)
	}
	if got.PageSize != MaxPageSize {
		t.Fatalf("expected normalized PageSize=%d, got %d", MaxPageSize, got.PageSize)
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
