package settings

import (
	"errors"
	"time"
)

const (
	DefaultTimeout         = 60 * time.Second
	DefaultMaxSourceBytes  = 64 << 20
	DefaultMaxSolverOutput = 256 << 20
	MaxResponseBytes       = 256 << 20
)

type Config struct {
	Timeout         time.Duration
	MaxSourceBytes  int
	MaxSolverOutput int64
	OnClosed        func()
}

type Option func(*Config)

func Apply(options ...Option) (Config, error) {
	cfg := Config{Timeout: DefaultTimeout, MaxSourceBytes: DefaultMaxSourceBytes, MaxSolverOutput: DefaultMaxSolverOutput}
	for _, option := range options {
		option(&cfg)
	}
	if cfg.MaxSourceBytes <= 0 || cfg.MaxSolverOutput <= 0 {
		return Config{}, errors.New("analysis: source and solver output limits must be positive")
	}
	return cfg, nil
}
