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
	ProcessList    string
	PortList       string
	ServiceList    string
	OSInfo         string
	FirewallConfig string
	DefenderConfig string
}

type VersionCheck struct {
	Process string
	Command string
}

type Service struct {
	Name           string
	Keywords       []string
	ServiceNames   []string
	DefaultPorts   []string
	VersionChecks  []VersionCheck
	Running        bool
	Listening      bool
	ProcessMatches []string
	ServiceMatches []string
	ListeningPorts []string
	Version        string
}

func run(command string) string {
	output, _ := runWithError(command)
	return output
}

func runWithError(command string) (string, error) {

	fmt.Println("[EXEC]", command)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	executable := "powershell"
	if _, err := exec.LookPath(executable); err != nil {
		executable = "pwsh"
	}

	cmd := exec.CommandContext(ctx, executable, "-NoProfile", "-NonInteractive", "-Command", command)

	output, err := cmd.CombinedOutput()

	if ctx.Err() == context.DeadlineExceeded {
		fmt.Println("[TIMEOUT]", command)
		return "", ctx.Err()
	}

	if err != nil {
		fmt.Println("[ERROR]", err.Error())
		return strings.TrimSpace(string(output)), err
	}

	fmt.Println("[DONE]", command)

	return strings.TrimSpace(string(output)), nil
}

func collectRuntimeData() RuntimeData {

	processList := run("Get-Process | Select-Object ProcessName,Id | Format-Table -AutoSize | Out-String -Width 4096")
	portList := run("Get-NetTCPConnection -State Listen | Select-Object LocalAddress,LocalPort,OwningProcess | Format-Table -AutoSize | Out-String -Width 4096")
	serviceList := run("Get-Service | Where-Object Status -eq 'Running' | Select-Object Name,DisplayName,Status,StartType | ConvertTo-Csv -NoTypeInformation | Out-String -Width 4096")
	osInfo := run("Get-CimInstance Win32_OperatingSystem | Select-Object Caption,Version,BuildNumber,InstallDate,LastBootUpTime | Format-List | Out-String -Width 4096")
	firewallConfig := run("Get-NetFirewallProfile | Select-Object Name,Enabled,DefaultInboundAction,DefaultOutboundAction | Format-Table -AutoSize | Out-String -Width 4096")
	defenderConfig := run("Get-MpComputerStatus | Select-Object AMServiceEnabled,AntivirusEnabled,RealTimeProtectionEnabled,AntispywareEnabled | Format-List | Out-String -Width 4096")

	fmt.Println("[OK] Runtime collection complete")
	fmt.Println()

	return RuntimeData{
		ProcessList:    processList,
		PortList:       portList,
		ServiceList:    serviceList,
		OSInfo:         osInfo,
		FirewallConfig: firewallConfig,
		DefenderConfig: defenderConfig,
	}
}

func (s Service) IsActive() bool {
	return s.Running || s.Listening
}

func (r RuntimeData) HasAnyPort(ports ...string) bool {
	for _, port := range ports {
		if strings.Contains(r.PortList, " "+port+" ") || strings.Contains(r.PortList, ":"+port) {
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
	if len(s.ServiceMatches) > 0 {
		parts = append(parts, "service="+strings.Join(s.ServiceMatches, ","))
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
		"rdp": {
			Name:         "Remote Desktop Services",
			Keywords:     []string{"termsrv"},
			ServiceNames: []string{"termservice"},
			DefaultPorts: []string{"3389"},
		},
		"remoteRegistry": {
			Name:         "Remote Registry",
			Keywords:     []string{"remoteregistry"},
			ServiceNames: []string{"remoteregistry"},
		},
		"iis": {
			Name:         "IIS",
			Keywords:     []string{"w3wp", "inetinfo"},
			ServiceNames: []string{"w3svc", "iisadmin"},
			DefaultPorts: []string{"80", "443"},
		},
		"mssql": {
			Name:         "SQL Server",
			Keywords:     []string{"sqlservr"},
			ServiceNames: []string{"mssqlserver", "sqlserveragent"},
			DefaultPorts: []string{"1433"},
		},
		"snmp": {
			Name:         "SNMP",
			Keywords:     []string{"snmp"},
			ServiceNames: []string{"snmp"},
			DefaultPorts: []string{"161"},
		},
		"ftp": {
			Name:         "FTP",
			Keywords:     []string{"ftpsvc", "filezilla", "ftp"},
			ServiceNames: []string{"ftpsvc", "msftpsvc"},
			DefaultPorts: []string{"21"},
		},
		"telnet": {
			Name:         "Telnet",
			Keywords:     []string{"tlntsvr", "telnet"},
			ServiceNames: []string{"tlntsvr"},
			DefaultPorts: []string{"23"},
		},
		"smtp": {
			Name:         "SMTP",
			Keywords:     []string{"smtpsvc", "smtpsvc1"},
			ServiceNames: []string{"smtpsvc"},
			DefaultPorts: []string{"25", "587"},
		},
		"smb": {
			Name:         "SMB",
			Keywords:     []string{"system"},
			ServiceNames: []string{"lanmanserver"},
			DefaultPorts: []string{"139", "445"},
		},
		"defender": {
			Name:         "Windows Defender",
			Keywords:     []string{"msmpeng"},
			ServiceNames: []string{"windefend"},
		},
		"firewall": {
			Name:         "Windows Firewall",
			Keywords:     []string{"mpssvc"},
			ServiceNames: []string{"mpssvc"},
		},
		"windowsUpdate": {
			Name:         "Windows Update",
			Keywords:     []string{"wuauclt", "usoclient"},
			ServiceNames: []string{"wuauserv"},
		},
	}

	fmt.Println("================================")
	fmt.Println("[*] Detecting services...")
	fmt.Println("================================")

	for key, service := range services {

		fmt.Println("--------------------------------")
		fmt.Println("[CHECK]", service.Name)

		var processMatches []string
		var serviceMatches []string
		var listeningPorts []string

		for _, keyword := range service.Keywords {

			fmt.Println("  -> searching process:", keyword)

			if strings.Contains(strings.ToLower(runtime.ProcessList), strings.ToLower(keyword)) {

				fmt.Println("     [FOUND PROCESS]", keyword)

				processMatches = append(processMatches, keyword)
			}
		}

		for _, serviceName := range service.ServiceNames {

			fmt.Println("  -> searching service:", serviceName)

			if strings.Contains(strings.ToLower(runtime.ServiceList), strings.ToLower(serviceName)) {

				fmt.Println("     [FOUND SERVICE]", serviceName)

				serviceMatches = append(serviceMatches, serviceName)
			}
		}

		for _, port := range service.DefaultPorts {

			fmt.Println("  -> checking port:", port)

			if runtime.HasAnyPort(port) {

				fmt.Println("     [LISTENING]", port)

				listeningPorts = append(listeningPorts, port)
			}
		}

		service.ProcessMatches = processMatches
		service.ServiceMatches = serviceMatches
		service.ListeningPorts = listeningPorts

		service.Running = len(processMatches) > 0 || len(serviceMatches) > 0
		service.Listening = len(listeningPorts) > 0

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
