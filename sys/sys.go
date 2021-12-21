package sys

import (
	"context"
	"net"
	"strconv"
)

type keyType int

var configKey keyType = keyType(10)

type config struct {
	base         string
	auth         string
	authport     uint16
	authCertPath string
}

func (c *config) AuthConnstr() string {
	return net.JoinHostPort(c.base+"."+c.auth, strconv.Itoa(int(c.authport)))
}

func (c *config) Domain() string {
	return c.base
}

func (c *config) Validate() error {
	return nil
}

type Option func(*config)

func WithAuthHost(host string) Option {
	return func(c *config) {
		c.auth = host
	}
}

func WithAuthPort(port uint16) Option {
	return func(c *config) {
		c.authport = port
	}
}

func WithAuthCert(path string) Option {
	return func(c *config) {
		c.authCertPath = path
	}
}

func ContextWithConfig(ctx context.Context, sysDomain string, opts ...Option) (context.Context, error) {
	cfg := &config{
		base:     sysDomain,
		auth:     "auth",
		authport: 8181,
	}
	for _, o := range opts {
		o(cfg)
	}
	if err := cfg.Validate(); err != nil {
		return ctx, err
	}
	return context.WithValue(ctx, configKey, cfg), nil
}

// func ConfigFromContext(ctx context.Context) (cfg *Config, ok bool) {
// 	c, ok := ctx.Value(configKey).(*Config)
// 	return c, ok
// }

func Domain(ctx context.Context) string {
	c, ok := ConfigFromContext(ctx)
	if ok {
		return c.Domain()
	}
	return ""
}

func AuthConnstr(ctx context.Context) string {
	c, ok := ConfigFromContext(ctx)
	if ok {
		return c.AuthConnstr()
	}
	return ""
}

func AuthCert(ctx context.Context) string {
	c, ok := ConfigFromContext(ctx)
	if ok {
		return c.authCertPath
	}
	return ""
}
