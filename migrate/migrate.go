// Package migrate 基于 golang-migrate 封装了一个精简的数据库迁移 runner：
// 读取指定目录下按版本号命名的 SQL 迁移文件，顺序执行并在数据库里记录已经执行到哪个版本，
// 供任意项目的 cmd/api 启动时或独立的 migrate 命令调用，避免每个项目各自手写迁移逻辑。
// 迁移文件命名遵循 golang-migrate 约定，例如 000001_create_users.up.sql / 000001_create_users.down.sql。
package migrate

import (
	"errors"
	"os"
	"path/filepath"

	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
)

// noMigrationFiles 判断 err 是否表示"迁移目录里一个迁移文件都没有"。
// golang-migrate 对这种情况返回的是 *os.PathError{Err: os.ErrNotExist}，而不是 migrate.ErrNoChange，
// 语义上属于"没有可执行的迁移"，Up 应该当成正常情况处理，而不是启动失败。
func noMigrationFiles(err error) bool {
	return errors.Is(err, os.ErrNotExist)
}

// Up 把 migrationsDir 目录下的迁移文件全部执行到最新版本；如果已经是最新版本则视为成功，不返回错误。
// dataSource 是标准的 PostgreSQL DSN，例如 "postgres://user:pass@host:5432/dbname?sslmode=disable"。
func Up(migrationsDir string, dataSource string) error {
	m, err := newMigrate(migrationsDir, dataSource)
	if err != nil {
		return err
	}
	defer closeMigrate(m)
	err = m.Up()
	if err != nil && !errors.Is(err, migrate.ErrNoChange) && !noMigrationFiles(err) {
		return err
	}
	return nil
}

// Down 回滚最近 steps 批迁移，steps 不传或非法值时默认回滚 1 步；只建议在本地开发排查问题时使用。
func Down(migrationsDir string, dataSource string, steps int) error {
	m, err := newMigrate(migrationsDir, dataSource)
	if err != nil {
		return err
	}
	defer closeMigrate(m)
	if steps <= 0 {
		steps = 1
	}
	err = m.Steps(-steps)
	if err != nil && !errors.Is(err, migrate.ErrNoChange) {
		return err
	}
	return nil
}

// Version 返回数据库当前已经执行到的迁移版本号，以及是否处于 dirty（上一次迁移执行到一半失败）状态。
// dirty 为 true 时必须人工确认数据库结构后再手动修复，不能直接继续跑后续迁移。
func Version(migrationsDir string, dataSource string) (version uint, dirty bool, err error) {
	m, err := newMigrate(migrationsDir, dataSource)
	if err != nil {
		return 0, false, err
	}
	defer closeMigrate(m)
	return m.Version()
}

// newMigrate 组装一个 golang-migrate 实例：迁移文件来自本地目录（source），目标数据库是 dataSource（database）。
func newMigrate(migrationsDir string, dataSource string) (*migrate.Migrate, error) {
	sourceURL, err := dirToFileURL(migrationsDir)
	if err != nil {
		return nil, err
	}
	return migrate.New(sourceURL, dataSource)
}

// dirToFileURL 把本地目录路径转成 golang-migrate 认识的 file:// URL。
// 单独处理是因为 Windows 路径（如 "C:\Users\x\migrations"）不能直接拼在 "file://" 后面：反斜杠不是合法的
// URL 分隔符，盘符后的冒号还会被误判成 URL 里的端口号。
// POSIX 绝对路径本身以 "/" 开头，拼成 "file:///home/..." 三斜杠，符合 golang-migrate 的解析逻辑；
// Windows 路径转成正斜杠后是 "C:/Users/..."（不以 "/" 开头），拼成 "file://C:/Users/..." 两斜杠，
// golang-migrate 会把 "C:" 当成 URL 的 host 部分、"/Users/..." 当成 path，拼接还原出合法的 "C:/Users/..."。
func dirToFileURL(dir string) (string, error) {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return "", err
	}
	return "file://" + filepath.ToSlash(abs), nil
}

// closeMigrate 释放 golang-migrate 内部持有的数据库连接，关闭失败不影响迁移结果，仅做最大努力清理。
func closeMigrate(m *migrate.Migrate) {
	_, _ = m.Close()
}
