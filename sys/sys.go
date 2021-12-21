// package sys is used to configure a vlpoc cluster. The other packages in the API will rely on
// this configuration to perform their work.
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

func (c *config) authConnstr() string {
	return net.JoinHostPort(c.auth+"."+c.base, strconv.Itoa(int(c.authport)))
}

func (c *config) domain() string {
	return c.base
}

func (c *config) validate() error {
	return nil
}

// Options are used to configure a context for use in a vlpoc cluster.
type Option func(*config)

// WithAuthHost sets the subdomain at which the authsrv can be reached.
// This is "auth" by default.
func WithAuthHost(host string) Option {
	return func(c *config) {
		c.auth = host
	}
}

// WithAuthPort sets the port at which the authsrv can be reached.
// This is 8181 by default.
func WithAuthPort(port uint16) Option {
	return func(c *config) {
		c.authport = port
	}
}

// Config injects vlpoc configuration into a context.Context. Required configuration is the
// system's base domain (sysDomain) and the path to the system's certificate authority cert
// (CAPath), to validate other certs from the system.
//
// Other configuration is achieved through Options.
func Config(ctx context.Context, sysDomain, CAPath string, opts ...Option) (context.Context, error) {
	cfg := &config{
		base:     sysDomain,
		auth:     "auth",
		authport: 8181,
		sysCA:    CAPath,
	}
	for _, o := range opts {
		o(cfg)
	}
	if err := cfg.validate(); err != nil {
		return ctx, err
	}
	return context.WithValue(ctx, configKey, cfg), nil
}

func configFromContext(ctx context.Context) (cfg *config, ok bool) {
	c, ok := ctx.Value(configKey).(*config)
	return c, ok
}

// Domain returns the currently-configured vlpoc domain from the Context.
func Domain(ctx context.Context) string {
	c, ok := configFromContext(ctx)
	if ok {
		return c.Domain()
	}
	return ""
}

// AuthConnstr returns a connection string that can be used to connect to the authsrv.
func AuthConnstr(ctx context.Context) string {
	c, ok := configFromContext(ctx)
	if ok {
		return c.authConnstr()
	}
	return ""
}

// CAPath returns a local path to the CA Certificate for the configured vlpoc cluster.
func CAPath(ctx context.Context) string {
	c, ok := configFromContext(ctx)
	if ok {
		return c.sysCA
	}
	return ""
}
