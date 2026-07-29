package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"
)

type ScanContext struct {
	Services map[string]Service
	Runtime  RuntimeData
}

type RuntimeData struct {
	ProcessList string
	PortList    string
	SRCList     string
	InetdConfig string
	OSLevel     string
	Errors      []string
}

type Service struct {
	Name            string
	ProcessKeywords []string
	SRCNames        []string
	InetdNames      []string
	DefaultPorts    []string
	Running         bool
	Listening       bool
	ProcessMatches  []string
	SRCMatches      []string
	InetdMatches    []string
	ListeningPorts  []string
}

func runProgram(name string, args ...string) (string, error) {
	fmt.Println("[EXEC]", name, strings.Join(args, " "))

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	path, err := exec.LookPath(name)
	if err != nil {
		fmt.Println("[ERROR]", err.Error())
		return "", err
	}

	cmd := exec.CommandContext(ctx, path, args...)
	output, err := cmd.CombinedOutput()
	if ctx.Err() == context.DeadlineExceeded {
		fmt.Println("[TIMEOUT]", name)
		return strings.TrimSpace(string(output)), ctx.Err()
	}
	if err != nil {
		fmt.Println("[ERROR]", err.Error())
		return strings.TrimSpace(string(output)), err
	}

	fmt.Println("[DONE]", name)
	return strings.TrimSpace(string(output)), nil
}

func collectRuntimeData() RuntimeData {
	runtimeData := RuntimeData{}

	if output, err := runProgram("ps", "-ef"); err != nil {
		runtimeData.Errors = append(runtimeData.Errors, err.Error())
	} else {
		runtimeData.ProcessList = output
	}
	if output, err := runProgram("netstat", "-an"); err != nil {
		runtimeData.Errors = append(runtimeData.Errors, err.Error())
	} else {
		runtimeData.PortList = output
	}
	if output, err := runProgram("lssrc", "-a"); err != nil {
		runtimeData.Errors = append(runtimeData.Errors, err.Error())
	} else {
		runtimeData.SRCList = output
	}
	if output, err := runProgram("oslevel", "-s"); err != nil {
		runtimeData.Errors = append(runtimeData.Errors, err.Error())
	} else {
		runtimeData.OSLevel = output
	}
	if data, err := os.ReadFile("/etc/inetd.conf"); err != nil {
		runtimeData.Errors = append(runtimeData.Errors, err.Error())
	} else {
		runtimeData.InetdConfig = string(data)
	}

	fmt.Println("[OK] AIX runtime collection complete")
	fmt.Println()
	return runtimeData
}

func (service Service) IsActive() bool {
	return service.Running || service.Listening
}

func (runtime RuntimeData) HasAnyPort(ports ...string) bool {
	for _, port := range ports {
		pattern := regexp.MustCompile(`(?m)(?:[:.*])` + regexp.QuoteMeta(port) + `(?:\s|$)`)
		if pattern.MatchString(runtime.PortList) {
			return true
		}
	}
	return false
}

func formatServiceStatus(service Service) string {
	var parts []string
	if len(service.ProcessMatches) > 0 {
		parts = append(parts, "process="+strings.Join(service.ProcessMatches, ","))
	}
	if len(service.SRCMatches) > 0 {
		parts = append(parts, "src="+strings.Join(service.SRCMatches, ","))
	}
	if len(service.InetdMatches) > 0 {
		parts = append(parts, "inetd="+strings.Join(service.InetdMatches, ","))
	}
	if len(service.ListeningPorts) > 0 {
		parts = append(parts, "ports="+strings.Join(service.ListeningPorts, ","))
	}
	if len(parts) == 0 {
		return "not_active"
	}
	return strings.Join(parts, " ")
}

func anyServiceActive(services map[string]Service, keys ...string) bool {
	for _, key := range keys {
		if service, ok := services[key]; ok && service.IsActive() {
			return true
		}
	}
	return false
}

func activeServiceLabels(services map[string]Service, keys ...string) []string {
	var labels []string
	for _, key := range keys {
		if service, ok := services[key]; ok && service.IsActive() {
			labels = append(labels, key+"("+formatServiceStatus(service)+")")
		}
	}
	return labels
}

func detectServices(runtime RuntimeData) map[string]Service {
	services := map[string]Service{
		"ssh": {
			Name: "SSH", ProcessKeywords: []string{"sshd"}, SRCNames: []string{"sshd"}, DefaultPorts: []string{"22"},
		},
		"telnet": {
			Name: "Telnet", ProcessKeywords: []string{"telnetd"}, InetdNames: []string{"telnet"}, DefaultPorts: []string{"23"},
		},
		"finger": {
			Name: "Finger", ProcessKeywords: []string{"fingerd"}, InetdNames: []string{"finger"}, DefaultPorts: []string{"79"},
		},
		"ftp": {
			Name: "FTP", ProcessKeywords: []string{"ftpd", "in.ftpd"}, InetdNames: []string{"ftp"}, DefaultPorts: []string{"21"},
		},
		"dns": {
			Name: "DNS", ProcessKeywords: []string{"named"}, SRCNames: []string{"named"}, DefaultPorts: []string{"53"},
		},
		"snmp": {
			Name: "SNMP", ProcessKeywords: []string{"snmpd"}, SRCNames: []string{"snmpd"}, DefaultPorts: []string{"161"},
		},
		"mail": {
			Name: "Mail", ProcessKeywords: []string{"sendmail"}, SRCNames: []string{"sendmail"}, DefaultPorts: []string{"25", "587"},
		},
		"nfs": {
			Name: "NFS", ProcessKeywords: []string{"nfsd", "biod", "rpc.mountd"}, SRCNames: []string{"nfs", "nfsd", "biod"}, DefaultPorts: []string{"2049"},
		},
		"automount": {
			Name: "Automount", ProcessKeywords: []string{"automountd"}, SRCNames: []string{"automountd"},
		},
		"rpc": {
			Name: "RPC", ProcessKeywords: []string{"portmap", "rpcbind", "rpc.statd", "rpc.lockd"}, SRCNames: []string{"portmap", "rpcbind"}, DefaultPorts: []string{"111"},
		},
		"nis": {
			Name: "NIS", ProcessKeywords: []string{"ypserv", "ypbind", "rpc.yppasswdd"}, SRCNames: []string{"ypserv", "ypbind"},
		},
		"rsh": {
			Name: "RSH", ProcessKeywords: []string{"rshd", "rlogind", "rexecd"}, InetdNames: []string{"shell", "login", "exec"}, DefaultPorts: []string{"512", "513", "514"},
		},
		"tftp": {
			Name: "TFTP", ProcessKeywords: []string{"tftpd"}, InetdNames: []string{"tftp"}, DefaultPorts: []string{"69"},
		},
		"talk": {
			Name: "Talk", ProcessKeywords: []string{"talkd", "ntalkd"}, InetdNames: []string{"talk", "ntalk"}, DefaultPorts: []string{"517", "518"},
		},
		"dos": {
			Name: "DoS legacy services", InetdNames: []string{"echo", "discard", "daytime", "chargen"}, DefaultPorts: []string{"7", "9", "13", "19"},
		},
	}

	processList := strings.ToLower(runtime.ProcessList)
	activeSRC := parseActiveSRC(runtime.SRCList)
	activeInetd := parseActiveInetd(runtime.InetdConfig)

	for key, service := range services {
		for _, keyword := range service.ProcessKeywords {
			if strings.Contains(processList, strings.ToLower(keyword)) {
				service.ProcessMatches = append(service.ProcessMatches, keyword)
			}
		}
		for _, name := range service.SRCNames {
			if activeSRC[strings.ToLower(name)] {
				service.SRCMatches = append(service.SRCMatches, name)
			}
		}
		for _, name := range service.InetdNames {
			if activeInetd[strings.ToLower(name)] {
				service.InetdMatches = append(service.InetdMatches, name)
			}
		}
		for _, port := range service.DefaultPorts {
			if runtime.HasAnyPort(port) {
				service.ListeningPorts = append(service.ListeningPorts, port)
			}
		}

		service.Running = len(service.ProcessMatches)+len(service.SRCMatches)+len(service.InetdMatches) > 0
		service.Listening = len(service.ListeningPorts) > 0
		services[key] = service
	}

	return services
}

func parseActiveSRC(raw string) map[string]bool {
	active := make(map[string]bool)
	for _, line := range strings.Split(raw, "\n") {
		fields := strings.Fields(strings.ToLower(line))
		if len(fields) > 0 && fields[len(fields)-1] == "active" {
			active[fields[0]] = true
		}
	}
	return active
}

func parseActiveInetd(raw string) map[string]bool {
	active := make(map[string]bool)
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(strings.ToLower(line))
		if len(fields) > 0 {
			active[fields[0]] = true
		}
	}
	return active
}
