package main

import (
	"context"
	"fmt"
	"time"

	"github.com/vlpoc/proto/exec"
)

type ExecSrv struct {
	exec.UnimplementedExecServer
}

func (e *ExecSrv) Execute(ctx context.Context, spec *exec.ExeSpec) (*exec.ExeResponse, error) {
	return nil, fmt.Errorf("NOT IMPLEMENTED")
}

func main() {
	for {
		time.Sleep(10 * time.Second)
	}
}
