package main

import (
	"fmt"
	"os"
	"strings"
)

type dsmU37Path struct {
	Path  string
	Mode  os.FileMode
	IsDir bool
}

type U37Input struct {
	Paths []dsmU37Path
}

func checkU37(ctx ScanContext) CheckResult {
	input, errs := loadU37Input(ctx)
	result := evalU37(input)
	result.Code = "U-37"
	result.Description = "Cron and DSM Task Scheduler configuration permissions should be restricted."
	return resultWithErrors(result, errs)
}

func loadU37Input(_ ScanContext) (U37Input, []string) {
	input := U37Input{}
	var errs []string
	for _, path := range []string{
		"/etc/crontab",
		"/etc/cron.d",
		"/var/spool/cron",
		"/var/spool/cron/crontabs",
		"/usr/syno/etc/synoschedtask.conf",
		"/usr/syno/etc/synoschedtask",
	} {
		info, err := os.Stat(path)
		if err == nil {
			input.Paths = append(input.Paths, dsmU37Path{Path: path, Mode: info.Mode().Perm(), IsDir: info.IsDir()})
		} else if !os.IsNotExist(err) {
			errs = append(errs, path+": "+err.Error())
		}
	}
	return input, errs
}

func evalU37(input U37Input) CheckResult {
	var raw, unsafe []string
	for _, item := range input.Paths {
		line := fmt.Sprintf("%s mode=%04o", item.Path, item.Mode)
		raw = append(raw, line)
		if dsmU37Unsafe(item) {
			unsafe = append(unsafe, line)
		}
	}
	if len(input.Paths) == 0 {
		return CheckResult{
			Status:          Manual,
			RawConfig:       "checked_paths=/etc/crontab,/etc/cron.d,/var/spool/cron,/var/spool/cron/crontabs,/usr/syno/etc/synoschedtask.conf,/usr/syno/etc/synoschedtask; found=0",
			ProcessedConfig: "scheduler_config=evidence_unavailable",
		}
	}
	if len(unsafe) > 0 {
		return CheckResult{Status: Vulnerable, RawConfig: strings.Join(raw, "\n"), ProcessedConfig: "scheduler_permissions=unsafe", VulnerableConfig: strings.Join(unsafe, "\n")}
	}
	return CheckResult{Status: Good, RawConfig: strings.Join(raw, "\n"), ProcessedConfig: "scheduler_permissions=safe"}
}

func dsmU37Unsafe(item dsmU37Path) bool {
	if item.IsDir {
		return item.Mode.Perm()&0027 != 0
	}
	return item.Mode.Perm()&0137 != 0
}
