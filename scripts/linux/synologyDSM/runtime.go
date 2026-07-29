package main

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

type CommandExecutor interface {
	Run(context.Context, string, ...string) (string, error)
}

type programExecutor struct{}

func (programExecutor) Run(ctx context.Context, name string, args ...string) (string, error) {
	return runProgram(ctx, name, args...)
}

type RuntimeData struct {
	ProcessList string   `json:"-"`
	PortList    string   `json:"-"`
	PackageList string   `json:"-"`
	Errors      []string `json:"errors,omitempty"`
}

type commandVariant struct {
	name string
	args []string
}

func runProgram(ctx context.Context, name string, args ...string) (string, error) {
	command := exec.CommandContext(ctx, name, args...)
	output, err := command.CombinedOutput()
	if err != nil {
		return string(output), fmt.Errorf("%s: %w", name, err)
	}
	return string(output), nil
}

func collectRuntimeData(ctx context.Context, executor CommandExecutor, timeout time.Duration) RuntimeData {
	var data RuntimeData

	process, err := runFirst(ctx, executor, timeout, []commandVariant{
		{name: "ps", args: []string{"-ef"}},
		{name: "ps", args: []string{"w"}},
		{name: "ps"},
	})
	if err != nil {
		data.Errors = append(data.Errors, "process collection: "+err.Error())
	} else {
		data.ProcessList = process
	}

	ports, err := runFirst(ctx, executor, timeout, []commandVariant{
		{name: "ss", args: []string{"-lntup"}},
		{name: "netstat", args: []string{"-tulnp"}},
		{name: "netstat", args: []string{"-an"}},
	})
	if err != nil {
		data.Errors = append(data.Errors, "port collection: "+err.Error())
	} else {
		data.PortList = ports
	}

	packages, err := runFirst(ctx, executor, timeout, []commandVariant{
		{name: "synopkg", args: []string{"list"}},
	})
	if err != nil {
		data.Errors = append(data.Errors, "package collection: "+err.Error())
	} else {
		data.PackageList = packages
	}

	return data
}

func runFirst(ctx context.Context, executor CommandExecutor, timeout time.Duration, variants []commandVariant) (string, error) {
	var failures []string
	for _, variant := range variants {
		commandCtx, cancel := context.WithTimeout(ctx, timeout)
		output, err := executor.Run(commandCtx, variant.name, variant.args...)
		cancel()
		if err == nil {
			return output, nil
		}
		failures = append(failures, fmt.Sprintf("%s: %v", variant.name, err))
	}
	return "", fmt.Errorf("all command variants failed (%s)", strings.Join(failures, "; "))
}
