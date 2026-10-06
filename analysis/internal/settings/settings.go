package settings

import (
	"errors"
	"time"
)

const MaxResponseBytes = 256 << 20

type Config struct {
	Timeout         time.Duration
	MaxSourceBytes  int
	MaxSolverOutput int64
	OnClosed        func()
}

type Option func(*Config)

func Apply(options ...Option) (Config, error) {
	cfg := Config{Timeout: 60 * time.Second, MaxSourceBytes: 64 << 20, MaxSolverOutput: 256 << 20}
	for _, option := range options {
		option(&cfg)
	}
	if cfg.MaxSourceBytes <= 0 || cfg.MaxSolverOutput <= 0 {
		return Config{}, errors.New("analysis: source and solver output limits must be positive")
	}
	return cfg, nil
}
