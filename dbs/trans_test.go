package dbs

import (
	"errors"
	"os"
	"strconv"
	"testing"

	_ "github.com/lib/pq"
	"xorm.io/xorm"
)

// dsnEnv 是本地联调时用来指定真实 PostgreSQL 连接串的环境变量名，没设置时跳过需要真实数据库的用例，
// 避免 bee 的测试套件依赖某台机器上恰好存在的数据库。
const dsnEnv = "BEE_TEST_POSTGRES_DSN"

// TestTransactionRunnerAddAppends 验证 Add 真的把操作追加进了 Orders。
//
// 这是回归测试：Add 原本是值接收者，append 出来的新切片只写进了副本，
// 调用方的 Orders 永远是空的，Run 会一条操作都不执行却返回 nil，
// 让人以为事务成功了。这种失败方式不会报错，只会静默丢数据。
func TestTransactionRunnerAddAppends(t *testing.T) {
	var runner TransactionRunner

	runner.Add(TransactionOrder{Table: "b", Id: 2})
	runner.Add(TransactionOrder{Table: "a", Id: 1})

	if len(runner.Orders) != 2 {
		t.Fatalf("expected Add to append 2 orders, got %d", len(runner.Orders))
	}
}

// TestTransactionRunnerSortsByTableThenID 验证排序规则：先 CustomOrder，再表名，最后主键。
// 顺序一致是这个类型存在的理由——并发事务按同样的顺序加锁才不会互相死锁。
func TestTransactionRunnerSortsByTableThenID(t *testing.T) {
	var runner TransactionRunner
	runner.Add(TransactionOrder{Table: "b", Id: 1})
	runner.Add(TransactionOrder{Table: "a", Id: 2})
	runner.Add(TransactionOrder{Table: "a", Id: 1})
	runner.Add(TransactionOrder{Table: "z", Id: 1, CustomOrder: -1})

	runner.sort()

	got := make([]string, 0, len(runner.Orders))
	for _, order := range runner.Orders {
		got = append(got, order.Table)
	}
	want := []string{"z", "a", "a", "b"}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("expected order %v, got %v", want, got)
		}
	}
	if runner.Orders[1].Id != 1 || runner.Orders[2].Id != 2 {
		t.Fatalf("expected same-table orders sorted by id, got %+v", runner.Orders)
	}
}

// newTestEngine 连接测试数据库并建一张临时表，用于验证事务的提交与回滚。
func newTestEngine(t *testing.T) *xorm.Engine {
	t.Helper()
	dsn := os.Getenv(dsnEnv)
	if dsn == "" {
		t.Skipf("skip: 未设置 %s，跳过需要真实 PostgreSQL 的用例", dsnEnv)
	}
	engine, err := xorm.NewEngine("postgres", dsn)
	if err != nil {
		t.Fatalf("NewEngine() error: %v", err)
	}
	t.Cleanup(func() { _ = engine.Close() })

	if _, err = engine.Exec(`CREATE TABLE IF NOT EXISTS bee_trans_test (id BIGINT PRIMARY KEY)`); err != nil {
		t.Fatalf("create test table failed: %v", err)
	}
	if _, err = engine.Exec(`TRUNCATE bee_trans_test`); err != nil {
		t.Fatalf("truncate test table failed: %v", err)
	}
	t.Cleanup(func() { _, _ = engine.Exec(`DROP TABLE IF EXISTS bee_trans_test`) })
	return engine
}

// countRows 返回临时表当前的行数。
// COUNT(*) 的具体 Go 类型由驱动决定（观察到过 int32 和 int64），统一转成字符串再解析，
// 免得测试因为驱动版本换了整数宽度就挂掉。
func countRows(t *testing.T, engine *xorm.Engine) int64 {
	t.Helper()
	rows, err := engine.QueryString(`SELECT COUNT(*) AS c FROM bee_trans_test`)
	if err != nil {
		t.Fatalf("count query failed: %v", err)
	}
	count, err := strconv.ParseInt(rows[0]["c"], 10, 64)
	if err != nil {
		t.Fatalf("unexpected count value %q: %v", rows[0]["c"], err)
	}
	return count
}

// TestTransactionCommits 验证 fn 返回 nil 时事务提交，且步骤按调用顺序执行。
func TestTransactionCommits(t *testing.T) {
	engine := newTestEngine(t)

	err := Transaction(engine, func(session *xorm.Session) error {
		if _, err := session.Exec(`INSERT INTO bee_trans_test (id) VALUES (1)`); err != nil {
			return err
		}
		_, err := session.Exec(`INSERT INTO bee_trans_test (id) VALUES (2)`)
		return err
	})
	if err != nil {
		t.Fatalf("Transaction() error: %v", err)
	}

	if got := countRows(t, engine); got != 2 {
		t.Fatalf("expected 2 committed rows, got %d", got)
	}
}

// TestTransactionRollsBack 验证 fn 返回错误时整个事务回滚，且原始错误被原样抛回。
// 错误必须能透传：调用方要靠它判断业务错误码，被回滚逻辑吞掉就只剩一个笼统的失败。
func TestTransactionRollsBack(t *testing.T) {
	engine := newTestEngine(t)
	sentinel := errors.New("business rule violated")

	err := Transaction(engine, func(session *xorm.Session) error {
		if _, execErr := session.Exec(`INSERT INTO bee_trans_test (id) VALUES (1)`); execErr != nil {
			return execErr
		}
		return sentinel
	})

	if !errors.Is(err, sentinel) {
		t.Fatalf("expected the original error to propagate, got %v", err)
	}
	if got := countRows(t, engine); got != 0 {
		t.Fatalf("expected the insert to be rolled back, got %d rows", got)
	}
}
