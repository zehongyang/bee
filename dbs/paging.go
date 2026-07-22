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

// BuildCursorResult 根据 ApplyCursor 查出来的记录（可能比 limit 多一条）计算出游标分页的元信息，
// 并把多查出来的那一条从返回结果里截掉。getID 用于取出每条记录的自增主键，items 必须已经按主键升序排列。
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
