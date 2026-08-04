package dbs

import (
	"fmt"
	"github.com/cespare/xxhash"
	_ "github.com/go-sql-driver/mysql"
	_ "github.com/lib/pq"
	_ "github.com/mattn/go-sqlite3"
	"github.com/zehongyang/bee/config"
	"github.com/zehongyang/bee/logger"
	"github.com/zehongyang/bee/utils"
	"sync"
	"time"
	"xorm.io/xorm"
)

var globalDBS = &DBEngine{
	engines: make(map[string]*xorm.Engine),
}

type DBConfig struct {
	DBS  []*DBSConfig
	dbMp map[string]*DBSConfig
}

type DBSConfig struct {
	Name               string
	Driver             string
	DataSource         string
	MaxIdle            int
	MaxConn            int
	MaxLifeTimeSeconds int
}

var getDBConfig = utils.Single(func() *DBConfig {
	var conf DBConfig
	err := config.Load(&conf)
	if err != nil {
		logger.Fatal().Err(err).Msg("Load DB config failed")
	}
	conf.dbMp = make(map[string]*DBSConfig)
	for _, db := range conf.DBS {
		conf.dbMp[db.Name] = db
	}
	return &conf
})

type DBEngine struct {
	engines map[string]*xorm.Engine
	mu      sync.Mutex
}

type SplitTableConfig struct {
	SplitTable []*SplitTable
	stMp       map[string]*SplitTable
}

type SplitTable struct {
	TableName string
	Nums      int64
	DBName    string
	engine    *xorm.Engine
}

func (s *SplitTable) Num(id int64) *xorm.Session {
	return s.engine.Table(s.getTable(id))
}

func (s *SplitTable) String(str string) *xorm.Session {
	sum64 := xxhash.Sum64String(str)
	return s.engine.Table(s.getTable(int64(sum64)))
}

func (s *SplitTable) GetEngine() *xorm.Engine {
	return s.engine
}

func (s *SplitTable) getTable(num int64) string {
	if s.Nums <= 1 {
		return s.TableName
	}
	return fmt.Sprintf("%s%d", s.TableName, num%s.Nums+1)
}

var getSplitTableConfig = utils.Single(func() *SplitTableConfig {
	var conf SplitTableConfig
	err := config.Load(&conf)
	if err != nil {
		logger.Fatal().Err(err).Msg("Load Split table config failed")
	}
	conf.stMp = make(map[string]*SplitTable)
	for _, st := range conf.SplitTable {
		conf.stMp[st.TableName] = st
	}
	return &conf
})

// Get 按分表名取出分表句柄，用于配置了 splitTable 的场景。
// 表名没有在 splitTable 段登记时直接终止进程——分表配置写错属于部署事故，
// 让它在启动阶段暴露比线上路由到错误的表要好。
func Get(tableName string) *SplitTable {
	tableConfig := getSplitTableConfig()
	if tableConfig == nil {
		logger.Fatal().Str("tableName", tableName).Msg("Get Split table config failed")
		return nil
	}
	st, ok := tableConfig.stMp[tableName]
	if !ok || len(st.TableName) < 1 || len(st.DBName) < 1 {
		logger.Fatal().Str("tableName", tableName).Msg("Get Split table failed")
		return nil
	}
	if st.engine != nil {
		return st
	}
	globalDBS.mu.Lock()
	defer globalDBS.mu.Unlock()
	// 二次检查：拿锁期间可能已经有别的 goroutine 填好了。
	if st.engine == nil {
		st.engine = engineLocked(st.DBName)
	}
	return st
}

// GetDB 按 application.yml 里 dbs 段的 name 取出数据库引擎。
//
// 和 Get 的区别是不需要 splitTable 配置：绝大多数业务表并不分表，
// 为了拿一个引擎去维护一份和建表语句平行的表名清单没有意义，而且新增表时容易漏配。
// 两者共用同一份引擎缓存和连接池设置，同名数据库只会建一个引擎。
func GetDB(dbName string) *xorm.Engine {
	globalDBS.mu.Lock()
	defer globalDBS.mu.Unlock()
	return engineLocked(dbName)
}

// engineLocked 返回指定数据库的引擎，没有就按配置新建并放进缓存。
// 调用方必须已经持有 globalDBS.mu。配置缺失或连不通时终止进程：
// 业务接口离开数据库无法工作，带着一个连不上的库启动只会让每个请求都失败。
func engineLocked(dbName string) *xorm.Engine {
	if egn, ok := globalDBS.engines[dbName]; ok {
		return egn
	}
	dbConfig := getDBConfig()
	dbsConfig, ok := dbConfig.dbMp[dbName]
	if !ok {
		logger.Fatal().Str("dbName", dbName).Msg("Get DB config failed")
		return nil
	}
	egn, err := xorm.NewEngine(dbsConfig.Driver, dbsConfig.DataSource)
	if err != nil {
		logger.Fatal().Err(err).Str("dbName", dbName).Any("cfg", dbsConfig).Msg("NewEngine failed")
		return nil
	}
	egn.SetMaxIdleConns(dbsConfig.MaxIdle)
	egn.SetMaxOpenConns(dbsConfig.MaxConn)
	egn.SetConnMaxLifetime(time.Second * time.Duration(dbsConfig.MaxLifeTimeSeconds))
	if err = egn.Ping(); err != nil {
		logger.Fatal().Err(err).Str("dbName", dbName).Msg("Ping failed")
		return nil
	}
	globalDBS.engines[dbName] = egn
	return egn
}
