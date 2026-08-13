package dbs

import "xorm.io/xorm"

// DefaultPageSize 是调用方没有指定 limit 时使用的默认每页条数。
const DefaultPageSize = 20

// MaxPageSize 是允许的单页最大条数，防止调用方传入超大 limit 导致一次查询拖垮数据库。
const MaxPageSize = 200

// CursorPage 描述一次游标分页查询的请求参数：AfterID 为上一页最后一条记录的自增主键（0 表示从第一页开始），
// Limit 为本页最多返回多少条，不传或非法值时会被 ApplyCursor 归一化为 DefaultPageSize/MaxPageSize。
type CursorPage struct {
	AfterID int64
	Limit   int
}

// CursorResult 是一次游标分页查询之后附带返回的分页元信息，和业务自己的列表数据一起返回给调用方。
type CursorResult struct {
	NextAfterID int64 `json:"next_after_id"`
	HasMore     bool  `json:"has_more"`
}

// normalizeLimit 把调用方传入的 limit 归一化到 (0, MaxPageSize] 区间内，非法值时退回 DefaultPageSize。
func normalizeLimit(limit int) int {
	if limit <= 0 {
		return DefaultPageSize
	}
	if limit > MaxPageSize {
		return MaxPageSize
	}
	return limit
}

// ApplyCursor 把游标分页参数应用到 xorm.Session 上：按自增主键升序、只取大于 AfterID 的记录，
// 并且多查一条（limit+1）用于后续通过 BuildCursorResult 判断是否还有下一页，调用方不需要自己额外查 count。
// idColumn 是自增主键在数据库里的列名，例如 "id"。
func ApplyCursor(session *xorm.Session, idColumn string, page CursorPage) *xorm.Session {
	limit := normalizeLimit(page.Limit)
	if page.AfterID > 0 {
		session = session.Where(idColumn+" > ?", page.AfterID)
	}
	return session.Asc(idColumn).Limit(limit + 1)
}

// ApplyCursorDesc 是 ApplyCursor 的倒序版本：按自增主键降序、只取小于 AfterID 的记录。
//
// 面向"最新的排最前"的列表（消息、工单、订单这类），它们翻页是往更早翻，
// 用升序游标就得先知道最大 ID 才能起步，等于把分页逻辑推给调用方。
// 返回结果同样可以直接交给 BuildCursorResult：降序时最后一条是本页最小的 ID，
// 正好是下一页 "id < afterID" 要用的游标。
func ApplyCursorDesc(session *xorm.Session, idColumn string, page CursorPage) *xorm.Session {
	limit := normalizeLimit(page.Limit)
	if page.AfterID > 0 {
		session = session.Where(idColumn+" < ?", page.AfterID)
	}
	return session.Desc(idColumn).Limit(limit + 1)
}

// OffsetPage 描述一次 offset 分页查询的请求参数：Page 是从 1 开始的页码，PageSize 是每页条数。
//
// 游标分页（CursorPage）无法回答"总共多少条""跳到第 5 页"，而管理后台的表格恰恰要这两样。
// 面向用户的列表仍应优先用游标分页——它不需要 count，翻页时也不会因为数据插入而错位或重复。
type OffsetPage struct {
	Page     int
	PageSize int
}

// OffsetResult 是一次 offset 分页查询附带返回的分页元信息，和业务自己的列表数据一起返回给调用方。
type OffsetResult struct {
	Page      int   `json:"page"`
	PageSize  int   `json:"page_size"`
	Total     int64 `json:"total"`
	TotalPage int   `json:"total_page"`
}

// Normalize 把页码和每页条数归一化到合法区间：页码至少为 1，每页条数走和游标分页同一套
// DefaultPageSize / MaxPageSize 约束，避免调用方传入超大 PageSize 一次拖垮数据库。
func (p OffsetPage) Normalize() OffsetPage {
	page := p.Page
	if page <= 0 {
		page = 1
	}
	return OffsetPage{Page: page, PageSize: normalizeLimit(p.PageSize)}
}

// Offset 返回本页在结果集中的起始偏移量，等价于 (页码-1) * 每页条数。
func (p OffsetPage) Offset() int {
	normalized := p.Normalize()
	return (normalized.Page - 1) * normalized.PageSize
}

// ApplyOffset 把 offset 分页参数应用到 xorm.Session 上。
//
// 与 ApplyCursor 不同，这里不会多查一条：offset 分页判断有没有下一页靠的是总条数，
// 调用方需要自己先用 Count 查一次总数，再用 BuildOffsetResult 组装分页元信息。
// 排序由调用方自己指定——offset 分页必须有确定的排序，否则翻页结果不稳定。
func ApplyOffset(session *xorm.Session, page OffsetPage) *xorm.Session {
	normalized := page.Normalize()
	return session.Limit(normalized.PageSize, normalized.Offset())
}

// BuildOffsetResult 根据归一化后的分页参数和 Count 查出的总条数组装分页元信息。
// total 为 0 时 TotalPage 也是 0，前端据此渲染空列表而不是"第 1 页 / 共 1 页"。
func BuildOffsetResult(page OffsetPage, total int64) OffsetResult {
	normalized := page.Normalize()
	var totalPage int
	if total > 0 {
		totalPage = int((total + int64(normalized.PageSize) - 1) / int64(normalized.PageSize))
	}
	return OffsetResult{
		Page:      normalized.Page,
		PageSize:  normalized.PageSize,
		Total:     total,
		TotalPage: totalPage,
	}
}

// BuildCursorResult 根据 ApplyCursor / ApplyCursorDesc 查出来的记录（可能比 limit 多一条）计算出
// 游标分页的元信息，并把多查出来的那一条从返回结果里截掉。getID 用于取出每条记录的自增主键。
// items 必须已经按查询时使用的方向排好序——升序查询就是升序，降序查询就是降序，
// next_after_id 一律取截断后最后一条的主键。
func BuildCursorResult[T any](items []T, limit int, getID func(T) int64) ([]T, CursorResult) {
	limit = normalizeLimit(limit)
	hasMore := len(items) > limit
	if hasMore {
		items = items[:limit]
	}
	var nextAfterID int64
	if len(items) > 0 {
		nextAfterID = getID(items[len(items)-1])
	}
	return items, CursorResult{NextAfterID: nextAfterID, HasMore: hasMore}
}
