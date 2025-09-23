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
	Name       string
	Driver     string
	DataSource string
	MaxIdle    int
	MaxConn    int
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
	var err error
	dbConfig := getDBConfig()
	dbsConfig, ok := dbConfig.dbMp[tableName]
	if !ok {
		logger.Fatal().Str("tableName", tableName).Msg("Get DB config failed")
		return nil
	}
	globalDBS.mu.Lock()
	defer globalDBS.mu.Unlock()
	egn, ok := globalDBS.engines[st.DBName]
	if !ok {
		egn, err = xorm.NewEngine(dbsConfig.Driver, dbsConfig.DataSource)
		if err != nil {
			logger.Fatal().Err(err).Str("tableName", tableName).Any("cfg", dbsConfig).Msg("NewEngine failed")
			return nil
		}
		egn.SetMaxIdleConns(dbsConfig.MaxIdle)
		egn.SetMaxOpenConns(dbsConfig.MaxConn)
		err = egn.Ping()
		if err != nil {
			logger.Fatal().Err(err).Str("tableName", tableName).Msg("Ping failed")
			return nil
		}
		globalDBS.engines[st.DBName] = egn
	}
	if st.engine == nil {
		st.engine = egn
	}
	return st
}
