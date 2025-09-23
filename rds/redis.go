package rds

import (
	"context"
	"github.com/redis/go-redis/v9"
	"github.com/zehongyang/bee/config"
	"github.com/zehongyang/bee/logger"
	"github.com/zehongyang/bee/utils"
	"sync"
)

var globalRd = RDEngine{
	clients: make(map[string]*redis.Client),
}

type RDConfig struct {
	RDS  []*RDSConfig
	rdMp map[string]*RDSConfig
}

type RDSConfig struct {
	Name     string
	Addr     string
	Password string
	DB       int
	MaxIdle  int
	MaxConn  int
	client   *redis.Client
}

var getRDConfig = utils.Single(func() *RDConfig {
	var rdc RDConfig
	err := config.Load(&rdc)
	if err != nil {
		logger.Fatal().Err(err).Msg("load rds config failed")
		return nil
	}
	rdc.rdMp = make(map[string]*RDSConfig)
	for _, rd := range rdc.RDS {
		rdc.rdMp[rd.Name] = rd
	}
	return &rdc
})

type RDEngine struct {
	clients map[string]*redis.Client
	mu      sync.Mutex
}

func Get(name string) *redis.Client {
	rdConfig := getRDConfig()
	rc, ok := rdConfig.rdMp[name]
	if !ok {
		logger.Fatal().Str("name", name).Msg("Get rds config failed")
		return nil
	}
	if rc.client != nil {
		return rc.client
	}
	globalRd.mu.Lock()
	defer globalRd.mu.Unlock()
	client, ok := globalRd.clients[name]
	if !ok {
		client = redis.NewClient(&redis.Options{
			Addr:           rc.Addr,
			Password:       rc.Password,
			DB:             rc.DB,
			MaxIdleConns:   rc.MaxIdle,
			MaxActiveConns: rc.MaxConn,
		})
		err := client.Ping(context.Background()).Err()
		if err != nil {
			logger.Fatal().Err(err).Msg("Get rds config failed")
			return nil
		}
		globalRd.clients[name] = client
		rc.client = client
	}
	return client
}
