package sys

import (
	"context"
	"net"
	"strconv"
)

type keyType int

var configKey keyType = keyType(10)

type config struct {
	base     string
	auth     string
	authport uint16
	sysCA    string
}

func (c *config) AuthConnstr() string {
	return net.JoinHostPort(c.auth+"."+c.base, strconv.Itoa(int(c.authport)))
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

func WithCertAuthority(path string) Option {
	return func(c *config) {
		c.sysCA = path
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

func configFromContext(ctx context.Context) (cfg *config, ok bool) {
	c, ok := ctx.Value(configKey).(*config)
	return c, ok
}

func Domain(ctx context.Context) string {
	c, ok := configFromContext(ctx)
	if ok {
		return c.Domain()
	}
	return ""
}

func AuthConnstr(ctx context.Context) string {
	c, ok := configFromContext(ctx)
	if ok {
		return c.AuthConnstr()
	}
	return ""
}

func CAPath(ctx context.Context) string {
	c, ok := configFromContext(ctx)
	if ok {
		return c.sysCA
	}
	return ""
}
