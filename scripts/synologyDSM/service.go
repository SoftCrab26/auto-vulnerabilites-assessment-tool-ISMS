package main

import (
	"strconv"
	"strings"
	"unicode"
)

type Service struct {
	Name            string   `json:"name"`
	ProcessKeywords []string `json:"processKeywords,omitempty"`
	Ports           []int    `json:"ports,omitempty"`
	Running         bool     `json:"running"`
	Listening       bool     `json:"listening"`
	PackageHints    []string `json:"packageHints,omitempty"`
	IsActive        bool     `json:"isActive"`
}

func detectServices(runtime RuntimeData) []Service {
	services := []Service{
		{Name: "ssh", ProcessKeywords: []string{"sshd"}, Ports: []int{22}},
		{Name: "smb", ProcessKeywords: []string{"smbd", "synosmbd"}, Ports: []int{139, 445}, PackageHints: []string{"SMBService"}},
		{Name: "nginx", ProcessKeywords: []string{"nginx"}, Ports: []int{80, 443, 5000, 5001}},
		{Name: "ftp", ProcessKeywords: []string{"ftpd", "proftpd"}, Ports: []int{20, 21}, PackageHints: []string{"FTP"}},
		{Name: "snmp", ProcessKeywords: []string{"snmpd"}, Ports: []int{161, 162}, PackageHints: []string{"SNMP"}},
		{Name: "nfs", ProcessKeywords: []string{"nfsd", "rpc.mountd"}, Ports: []int{111, 2049}, PackageHints: []string{"NFS"}},
		{Name: "postgres", ProcessKeywords: []string{"postgres", "postmaster"}, Ports: []int{5432}, PackageHints: []string{"PostgreSQL"}},
		{Name: "quickconnect", ProcessKeywords: []string{"quickconnect", "synorelayd"}, PackageHints: []string{"QuickConnect"}},
	}

	listening := listeningPorts(runtime.PortList)
	for index := range services {
		service := &services[index]
		service.Running = containsAnyWord(runtime.ProcessList, service.ProcessKeywords)
		for _, port := range service.Ports {
			if listening[port] {
				service.Listening = true
				break
			}
		}
		packagePresent := containsAnyWord(runtime.PackageList, service.PackageHints)
		service.IsActive = service.Running || service.Listening || packagePresent
	}
	return services
}

func containsAnyWord(raw string, keywords []string) bool {
	lower := strings.ToLower(raw)
	for _, keyword := range keywords {
		if containsWord(lower, strings.ToLower(keyword)) {
			return true
		}
	}
	return false
}

func containsWord(raw, word string) bool {
	if word == "" {
		return false
	}
	for start := 0; start < len(raw); {
		index := strings.Index(raw[start:], word)
		if index < 0 {
			return false
		}
		index += start
		end := index + len(word)
		leftBoundary := index == 0 || !isWordCharacter(rune(raw[index-1]))
		rightBoundary := end == len(raw) || !isWordCharacter(rune(raw[end]))
		if leftBoundary && rightBoundary {
			return true
		}
		start = index + 1
	}
	return false
}

func isWordCharacter(character rune) bool {
	return unicode.IsLetter(character) || unicode.IsDigit(character) || character == '_'
}

func listeningPorts(raw string) map[int]bool {
	ports := make(map[int]bool)
	for _, line := range strings.Split(raw, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		protocol := strings.ToLower(fields[0])
		var endpoint string
		switch {
		case strings.HasPrefix(protocol, "tcp") && len(fields) >= 5 && strings.EqualFold(fields[1], "LISTEN"):
			endpoint = fields[4]
		case strings.HasPrefix(protocol, "udp") && len(fields) >= 5 && strings.EqualFold(fields[1], "UNCONN"):
			endpoint = fields[4]
		case strings.HasPrefix(protocol, "tcp") && len(fields) >= 6:
			if !containsFold(fields, "listen") {
				continue
			}
			endpoint = fields[3]
		case strings.HasPrefix(protocol, "udp") && len(fields) >= 4:
			endpoint = fields[3]
		default:
			continue
		}
		if port, ok := endpointPort(endpoint); ok {
			ports[port] = true
		}
	}
	return ports
}

func containsFold(values []string, target string) bool {
	for _, value := range values {
		if strings.EqualFold(value, target) {
			return true
		}
	}
	return false
}

func endpointPort(endpoint string) (int, bool) {
	endpoint = strings.TrimSpace(endpoint)
	index := strings.LastIndexByte(endpoint, ':')
	if index < 0 || index == len(endpoint)-1 {
		return 0, false
	}
	port, err := strconv.Atoi(endpoint[index+1:])
	if err != nil || port < 1 || port > 65535 {
		return 0, false
	}
	return port, true
}
