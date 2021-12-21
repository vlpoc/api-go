package main

import (
	"context"
	"fmt"

	// Not included in go.mod
	"github.com/vlpoc/api-go/auth"
	"github.com/vlpoc/api-go/sys"
)

func main() {
	ctx, err := sys.ContextWithConfig(context.Background(), "vlpoc.com",
		sys.WithCertAuthority("/Users/kyle.nusbaum/Library/Application Support/vlpoc-authsrv/ca.crt.pem"))
	if err != nil {
		fmt.Printf("Failed to configure vlpoc: %s\n", err)
		return
	}

	ctx, err = auth.Login(ctx, "kyle", "hello")
	if err != nil {
		fmt.Printf("Failed to log in to vlpoc: %s\n", err)
		return
	}

	if actor, ok := auth.GetActor(ctx); ok {
		fmt.Printf("Logged in as %s\n", actor)
	} else {
		fmt.Printf("Not logged in...\n")
	}
}
