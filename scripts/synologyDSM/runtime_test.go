package main

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"
)

type fakeCommandResponse struct {
	output string
	err    error
}

type fakeExecutor struct {
	responses map[string]fakeCommandResponse
	calls     []string
}

func (fake *fakeExecutor) Run(_ context.Context, name string, args ...string) (string, error) {
	key := strings.Join(append([]string{name}, args...), " ")
	fake.calls = append(fake.calls, key)
	response, ok := fake.responses[key]
	if !ok {
		return "", errors.New("unexpected command")
	}
	return response.output, response.err
}

func TestCollectRuntimeDataFallback(t *testing.T) {
	fake := &fakeExecutor{responses: map[string]fakeCommandResponse{
		"ps -ef":         {err: errors.New("unsupported option")},
		"ps w":           {output: "PID USER COMMAND\n1 root /sbin/init\n"},
		"ps":             {output: "must not be called"},
		"ss -lntup":      {err: errors.New("not installed")},
		"netstat -tulnp": {output: "tcp 0 0 0.0.0.0:22 0.0.0.0:* LISTEN\n"},
		"synopkg list":   {err: errors.New("permission denied")},
		"netstat -an":    {output: "must not be called"},
	}}

	data := collectRuntimeData(context.Background(), fake, time.Second)

	if !strings.HasPrefix(data.ProcessList, "PID") {
		t.Fatalf("unexpected process fallback output: %q", data.ProcessList)
	}
	if !strings.Contains(data.PortList, ":22") {
		t.Fatalf("unexpected port fallback output: %q", data.PortList)
	}
	if data.PackageList != "" || len(data.Errors) != 1 {
		t.Fatalf("package failure should be nonfatal and recorded: %+v", data)
	}
	wantCalls := []string{"ps -ef", "ps w", "ss -lntup", "netstat -tulnp", "synopkg list"}
	if !reflect.DeepEqual(fake.calls, wantCalls) {
		t.Fatalf("calls = %#v, want %#v", fake.calls, wantCalls)
	}
}

func TestListeningPortsIPv4IPv6AndFalsePositive(t *testing.T) {
	raw := strings.Join([]string{
		"Netid State Recv-Q Send-Q Local Address:Port Peer Address:Port",
		"tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:*",
		"tcp6 0 0 :::445 :::* LISTEN",
		"tcp LISTEN 0 128 [::]:1222 [::]:*",
		"tcp 0 0 10.0.0.2:5432 10.0.0.3:60000 ESTABLISHED",
	}, "\n")

	ports := listeningPorts(raw)
	if !ports[22] || !ports[445] || !ports[1222] {
		t.Fatalf("expected listening ports not parsed: %#v", ports)
	}
	if ports[5432] {
		t.Fatalf("established connection incorrectly treated as listener: %#v", ports)
	}

	services := detectServices(RuntimeData{PortList: raw})
	ssh := serviceByName(services, "ssh")
	if ssh == nil || !ssh.Listening {
		t.Fatalf("SSH listener not detected: %#v", ssh)
	}
	postgres := serviceByName(services, "postgres")
	if postgres == nil || postgres.Listening {
		t.Fatalf("port 5432 false positive: %#v", postgres)
	}

	onlySimilarPort := detectServices(RuntimeData{
		PortList: "tcp LISTEN 0 128 [::]:1222 [::]:*\n",
	})
	ssh = serviceByName(onlySimilarPort, "ssh")
	if ssh == nil || ssh.Listening {
		t.Fatalf("port 1222 incorrectly matched SSH port 22: %#v", ssh)
	}
}

func serviceByName(services []Service, name string) *Service {
	for index := range services {
		if services[index].Name == name {
			return &services[index]
		}
	}
	return nil
}
