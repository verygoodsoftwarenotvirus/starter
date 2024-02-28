package elasticsearch

import (
	"fmt"
	"time"

	"github.com/elastic/go-elasticsearch/v8"
)

type Config struct {
	Address               string        `json:"address"               toml:"address,omitempty"`
	Username              string        `json:"username"              toml:"username,omitempty"`
	Password              string        `json:"password"              toml:"password,omitempty"`
	CACert                []byte        `json:"caCert"                toml:"ca_cert,omitempty"`
	IndexOperationTimeout time.Duration `json:"indexOperationTimeout" toml:"index_operation_timeout,omitempty"`
}

func (cfg *Config) provideElasticsearchClient() (*elasticsearch.Client, error) {
	c, err := elasticsearch.NewClient(elasticsearch.Config{
		Addresses: []string{
			cfg.Address,
		},
		Username:      cfg.Username,
		Password:      cfg.Password,
		CACert:        cfg.CACert,
		RetryOnStatus: nil,
		MaxRetries:    10,
		Transport:     nil,
		Logger:        nil,
	})
	if err != nil {
		return nil, fmt.Errorf("initializing search client: %w", err)
	}

	return c, nil
}
