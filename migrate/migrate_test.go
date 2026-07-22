package migrate

import (
	"os"
	"testing"
)

// dsnEnv 是本地联调时用来指定真实 PostgreSQL 连接串的环境变量名，没设置时跳过需要真实数据库的用例，
// 避免 bee 的测试套件依赖某台机器上恰好存在的数据库。
const dsnEnv = "BEE_TEST_POSTGRES_DSN"

// TestUpWithEmptyMigrationsDirIsNoOp 验证迁移目录一个迁移文件都没有时，Up 不应该报错——
// 这是骨架阶段（业务表还没加迁移文件）时的正常状态，不应该导致依赖它的服务无法启动。
// 需要设置 BEE_TEST_POSTGRES_DSN 才会真正连接数据库执行，否则跳过。
func TestUpWithEmptyMigrationsDirIsNoOp(t *testing.T) {
	dsn := os.Getenv(dsnEnv)
	if dsn == "" {
		t.Skipf("skip: 未设置 %s，跳过需要真实 PostgreSQL 的用例", dsnEnv)
	}

	dir := t.TempDir()
	if err := Up(dir, dsn); err != nil {
		t.Fatalf("Up() on empty migrations dir should be a no-op, got error: %v", err)
	}
}
