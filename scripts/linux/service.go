package main

import (
	"context"
	"fmt"
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
}

type VersionCheck struct {
	Process string
	Command string
}

type Service struct {
	Name           string
	Keywords       []string
	DefaultPorts   []string
	VersionChecks  []VersionCheck
	Running        bool
	Listening      bool
	ProcessMatches []string
	ListeningPorts []string
	Version        string
}

func run(command string) string {

	fmt.Println("[EXEC]", command)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "bash", "-c", command)

	output, err := cmd.CombinedOutput()

	if ctx.Err() == context.DeadlineExceeded {
		fmt.Println("[TIMEOUT]", command)
		return ""
	}

	if err != nil {
		fmt.Println("[ERROR]", err.Error())
		return ""
	}

	fmt.Println("[DONE]", command)

	return strings.ToLower(string(output))
}

func collectRuntimeData() RuntimeData {

	processList := run("ps -ef")
	portList := run("ss -lntup")

	fmt.Println("[OK] Runtime collection complete")
	fmt.Println()

	return RuntimeData{
		ProcessList: processList,
		PortList:    portList,
	}
}

func (s Service) IsActive() bool {
	return s.Running || s.Listening
}

func (r RuntimeData) HasAnyPort(ports ...string) bool {
	for _, port := range ports {
		if strings.Contains(r.PortList, ":"+port) {
			return true
		}
	}
	return false
}

func formatServiceStatus(s Service) string {
	var parts []string
	if len(s.ProcessMatches) > 0 {
		parts = append(parts, "process="+strings.Join(s.ProcessMatches, ","))
	}
	if len(s.ListeningPorts) > 0 {
		parts = append(parts, "ports="+strings.Join(s.ListeningPorts, ","))
	}
	if s.Version != "" && s.Version != "NOT_RUNNING" {
		parts = append(parts, "version="+s.Version)
	}
	if len(parts) == 0 {
		return "not_active"
	}
	return strings.Join(parts, " ")
}

func anyServiceActive(services map[string]Service, keys ...string) bool {
	for _, key := range keys {
		if svc, ok := services[key]; ok && svc.IsActive() {
			return true
		}
	}
	return false
}

func activeServiceLabels(services map[string]Service, keys ...string) []string {
	var found []string
	for _, key := range keys {
		svc, ok := services[key]
		if !ok || !svc.IsActive() {
			continue
		}
		label := key
		if len(svc.ProcessMatches) > 0 {
			label += "(" + strings.Join(svc.ProcessMatches, ",") + ")"
		}
		found = append(found, label)
	}
	return found
}

func detectServices(runtime RuntimeData) map[string]Service {

	services := map[string]Service{
		"dns": {
			Name:         "DNS",
			Keywords:     []string{"named", "bind9", "dnsmasq"},
			DefaultPorts: []string{"53"},

			VersionChecks: []VersionCheck{
				{
					Process: "named",
					Command: "named -v",
				},
				{
					Process: "dnsmasq",
					Command: "dnsmasq --version",
				},
			},
		},

		"snmp": {
			Name:         "SNMP",
			Keywords:     []string{"snmpd"},
			DefaultPorts: []string{"161"},

			VersionChecks: []VersionCheck{
				{
					Process: "snmpd",
					Command: "snmpd --version",
				},
			},
		},
		"ssh": {
			Name:         "SSH",
			Keywords:     []string{"sshd"},
			DefaultPorts: []string{"22"},

			VersionChecks: []VersionCheck{
				{
					Process: "sshd",
					Command: "sshd -V",
				},
			},
		},

		"ftp": {
			Name:         "FTP",
			Keywords:     []string{"vsftpd", "proftpd", "ftpd"},
			DefaultPorts: []string{"21"},

			VersionChecks: []VersionCheck{
				{
					Process: "vsftpd",
					Command: "vsftpd -version",
				},
				{
					Process: "proftpd",
					Command: "proftpd -v",
				},
			},
		},

		"web": {
			Name:         "Web",
			Keywords:     []string{"httpd", "apache2", "nginx"},
			DefaultPorts: []string{"80", "443"},

			VersionChecks: []VersionCheck{
				{
					Process: "httpd",
					Command: "httpd -v",
				},
				{
					Process: "apache2",
					Command: "apache2 -v",
				},
				{
					Process: "nginx",
					Command: "nginx -v",
				},
			},
		},

		"mysql": {
			Name:         "MySQL",
			Keywords:     []string{"mysqld"},
			DefaultPorts: []string{"3306"},

			VersionChecks: []VersionCheck{
				{
					Process: "mysqld",
					Command: "mysqld --version",
				},
			},
		},

		"postgres": {
			Name:         "PostgreSQL",
			Keywords:     []string{"postgres"},
			DefaultPorts: []string{"5432"},

			VersionChecks: []VersionCheck{
				{
					Process: "postgres",
					Command: "postgres --version",
				},
			},
		},

		"telnet": {
			Name:         "Telnet",
			Keywords:     []string{"telnet", "in.telnetd"},
			DefaultPorts: []string{"23"},
		},

		"finger": {
			Name:         "Finger",
			Keywords:     []string{"finger", "in.fingerd"},
			DefaultPorts: []string{"79"},
		},

		"nfs": {
			Name:         "NFS",
			Keywords:     []string{"nfsd", "rpc.nfsd", "mountd"},
			DefaultPorts: []string{"2049"},
		},

		"automount": {
			Name:     "Automount",
			Keywords: []string{"automount", "autofs"},
		},

		"rpc": {
			Name:         "RPC",
			Keywords:     []string{"rpcbind", "portmap", "rpc.statd", "rpc.mountd"},
			DefaultPorts: []string{"111"},
		},

		"nis": {
			Name:     "NIS",
			Keywords: []string{"ypserv", "ypbind"},
		},

		"tftp": {
			Name:         "TFTP",
			Keywords:     []string{"tftp", "in.tftpd"},
			DefaultPorts: []string{"69"},
		},

		"talk": {
			Name:         "Talk",
			Keywords:     []string{"talk", "ntalk"},
			DefaultPorts: []string{"517", "518"},
		},

		"mail": {
			Name:         "Mail",
			Keywords:     []string{"sendmail", "postfix", "exim", "dovecot"},
			DefaultPorts: []string{"25", "587"},
		},

		"rsh": {
			Name:         "RSH",
			Keywords:     []string{"rsh", "rlogin", "rexec", "rshd", "rlogind"},
			DefaultPorts: []string{"513", "514"},
		},

		"dos": {
			Name:         "DoS",
			Keywords:     []string{"echo", "discard", "daytime", "chargen", "xinetd", "inetd"},
			DefaultPorts: []string{"7", "9", "13", "19"},
		},
	}

	fmt.Println("================================")
	fmt.Println("[*] Detecting services...")
	fmt.Println("================================")

	for key, service := range services {

		fmt.Println("--------------------------------")
		fmt.Println("[CHECK]", service.Name)

		var processMatches []string
		var listeningPorts []string

		// process detection
		for _, keyword := range service.Keywords {

			fmt.Println("  -> searching process:", keyword)

			if strings.Contains(runtime.ProcessList, strings.ToLower(keyword)) {

				fmt.Println("     [FOUND PROCESS]", keyword)

				processMatches = append(processMatches, keyword)
			}
		}

		// port detection
		for _, port := range service.DefaultPorts {

			fmt.Println("  -> checking port:", port)

			if strings.Contains(runtime.PortList, ":"+port) {

				fmt.Println("     [LISTENING]", port)

				listeningPorts = append(listeningPorts, port)
			}
		}

		service.ProcessMatches = processMatches
		service.ListeningPorts = listeningPorts

		service.Running = len(processMatches) > 0
		service.Listening = len(listeningPorts) > 0

		// version detection
		if service.Running {

			fmt.Println("  -> detecting version")

			service.Version = detectVersion(service)

			fmt.Println("     [VERSION]", service.Version)

		} else {
			service.Version = "NOT_RUNNING"
		}

		services[key] = service

		fmt.Println("[DONE]", service.Name)
		fmt.Println()
	}

	fmt.Println("================================")
	fmt.Println("[OK] Service detection complete")
	fmt.Println("================================")

	return services
}

func detectVersion(service Service) string {

	for _, check := range service.VersionChecks {

		// 실제 실행중인 process만 version 확인
		if !contains(service.ProcessMatches, check.Process) {
			continue
		}

		output := run(check.Command)

		version := extractVersion(output)

		if version != "UNKNOWN" {
			return version
		}
	}

	return "UNKNOWN"
}

func contains(arr []string, target string) bool {

	for _, item := range arr {
		if item == target {
			return true
		}
	}

	return false
}

func extractVersion(text string) string {

	re := regexp.MustCompile(`\d+(\.\d+)+`)

	match := re.FindString(text)

	if match == "" {
		return "UNKNOWN"
	}

	return match
}
