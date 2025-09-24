package dbs

import (
	"sort"
	"xorm.io/xorm"
)

type TransactionOrder struct {
	Table string
	Id    int64
	Func  TransactionFunc
}

type TransactionFunc func(ses *xorm.Session) (err error)

type TransactionRunner struct {
	Orders []TransactionOrder
}

func (tr TransactionRunner) Add(to TransactionOrder) {
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
		if tr.Orders[i].Table != tr.Orders[j].Table {
			return tr.Orders[i].Table < tr.Orders[j].Table
		}
		return tr.Orders[i].Id < tr.Orders[j].Id
	})
}
