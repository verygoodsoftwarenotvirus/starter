package algolia

import (
	"time"
)

type Config struct {
	AppID   string        `json:"appID"       toml:"app_id,omitempty"`
	APIKey  string        `json:"writeAPIKey" toml:"write_api_key,omitempty"`
	Timeout time.Duration `json:"timeout"     toml:"timeout,omitempty"`
}
