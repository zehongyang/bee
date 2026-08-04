package dbs

import (
	"fmt"
	"sort"
	"xorm.io/xorm"
)

// Transaction 在一个数据库事务里按调用顺序执行 fn，fn 返回错误时回滚，返回 nil 时提交。
//
// 适用于步骤之间存在数据依赖的场景，例如"先插主记录拿到自增 ID，再用这个 ID 写关联记录"。
// 这类流程不能用 TransactionRunner——那个会先排序再执行，顺序不由调用方决定。
func Transaction(engine *xorm.Engine, fn func(session *xorm.Session) error) error {
	session := engine.NewSession()
	defer session.Close()

	if err := session.Begin(); err != nil {
		return fmt.Errorf("begin transaction failed: %w", err)
	}
	if err := fn(session); err != nil {
		// 回滚失败只影响清理，真正要往上抛的是业务错误本身，否则调用方拿不到错误原因。
		if rollbackErr := session.Rollback(); rollbackErr != nil {
			return fmt.Errorf("%w (rollback failed: %v)", err, rollbackErr)
		}
		return err
	}
	if err := session.Commit(); err != nil {
		return fmt.Errorf("commit transaction failed: %w", err)
	}
	return nil
}

type TransactionOrder struct {
	Table       string
	Id          int64
	CustomOrder int64
	Func        TransactionFunc
}

type TransactionFunc func(ses *xorm.Session) (err error)

// TransactionRunner 把多个写操作按固定顺序（CustomOrder、表名、主键）排序后放进同一个事务，
// 用于让并发事务以一致的顺序加锁，避免互相死锁。
// 步骤之间有数据依赖、必须按调用顺序执行时请改用 Transaction。
type TransactionRunner struct {
	Orders []TransactionOrder
}

// Add 追加一个待执行的操作。
// 必须用指针接收者：值接收者会让 append 的结果写进副本，调用方的 Orders 永远是空的。
func (tr *TransactionRunner) Add(to TransactionOrder) {
	tr.Orders = append(tr.Orders, to)
}

func (tr TransactionRunner) Run(db *xorm.Engine) error {
	tr.sort()
	_, err := db.Transaction(func(ses *xorm.Session) (interface{}, error) {
		for _, to := range tr.Orders {
			err := to.Func(ses)
			if err != nil {
				return nil, err
			}
		}
		return nil, nil
	})
	return err
}

func (tr TransactionRunner) sort() {
	sort.Slice(tr.Orders, func(i, j int) bool {
		if tr.Orders[i].CustomOrder != tr.Orders[j].CustomOrder {
			return tr.Orders[i].CustomOrder < tr.Orders[j].CustomOrder
		}
		if tr.Orders[i].Table != tr.Orders[j].Table {
			return tr.Orders[i].Table < tr.Orders[j].Table
		}
		return tr.Orders[i].Id < tr.Orders[j].Id
	})
}
