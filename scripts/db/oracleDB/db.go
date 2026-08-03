package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"strings"
	"time"
)

const sqlColumnSeparator = "|~|"

// QueryRunner accepts only compile-time constant SELECT statements owned by this
// scanner. Callers must never pass environment values or other user input as SQL.
type QueryRunner interface {
	Query(context.Context, string) ([][]string, error)
}

type SQLPlusRunner struct {
	path        string
	connectSpec string
	timeout     time.Duration
	log         io.Writer
}

func newSQLPlusRunner(cfg Config) *SQLPlusRunner {
	return &SQLPlusRunner{
		path:        cfg.SQLPlusPath,
		connectSpec: cfg.connectSpec,
		timeout:     cfg.QueryTimeout,
	}
}

func (r *SQLPlusRunner) setLog(w io.Writer) {
	r.log = w
}

func (r *SQLPlusRunner) Query(parent context.Context, query string) ([][]string, error) {
	ctx, cancel := context.WithTimeout(parent, r.timeout)
	defer cancel()

	execLabel := r.path + " -L -S /nolog"
	if r.log != nil {
		fmt.Fprintln(r.log, "[EXEC]", execLabel)
	}

	// The argv is deliberately fixed. Authentication data is provided only over
	// stdin and must never be included in command arguments.
	cmd := exec.CommandContext(ctx, r.path, "-L", "-S", "/nolog")
	script := strings.Join([]string{
		"whenever sqlerror exit sql.sqlcode",
		"whenever oserror exit failure",
		"set heading off",
		"set feedback off",
		"set echo off",
		"set verify off",
		"set pagesize 0",
		"set linesize 32767",
		"set trimspool on",
		"set tab off",
		"set define off",
		"connect " + r.connectSpec,
		query,
		"exit",
		"",
	}, "\n")
	cmd.Stdin = strings.NewReader(script)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	if ctx.Err() != nil {
		if r.log != nil {
			fmt.Fprintln(r.log, "[ERROR] sqlplus query timed out")
		}
		return nil, errors.New("sqlplus query timed out")
	}
	if err != nil {
		detail := redactOracleError(stdout.String()+"\n"+stderr.String(), r.connectSpec)
		if r.log != nil {
			if detail == "" {
				fmt.Fprintln(r.log, "[ERROR] sqlplus query failed")
			} else {
				fmt.Fprintln(r.log, "[ERROR]", detail)
			}
		}
		if detail == "" {
			return nil, errors.New("sqlplus query failed")
		}
		return nil, fmt.Errorf("sqlplus query failed: %s", detail)
	}

	rows, err := parseSQLPlusRows(stdout.String())
	if err != nil {
		msg := redactOracleError(err.Error(), r.connectSpec)
		if r.log != nil {
			fmt.Fprintln(r.log, "[ERROR]", msg)
		}
		return nil, errors.New(msg)
	}
	if r.log != nil {
		fmt.Fprintln(r.log, "[DONE]", execLabel)
	}
	return rows, nil
}

type ScanContext struct {
	Runner      QueryRunner
	Metadata    DBMetadata
	MetadataErr error
}

func collectDBMetadata(ctx context.Context, runner QueryRunner) (DBMetadata, error) {
	const query = `SELECT d.name || '|~|' || d.db_unique_name || '|~|' ||
       i.version || '|~|' || d.database_role || '|~|' || d.open_mode
FROM v$database d CROSS JOIN v$instance i;`

	rows, err := runner.Query(ctx, query)
	if err != nil {
		return DBMetadata{}, fmt.Errorf("database metadata query failed: %s", redactOracleError(err.Error(), ""))
	}
	if len(rows) != 1 || len(rows[0]) != 5 {
		return DBMetadata{}, errors.New("database metadata query returned an unexpected row shape")
	}
	for _, value := range rows[0] {
		if strings.TrimSpace(value) == "" {
			return DBMetadata{}, errors.New("database metadata query returned an empty required value")
		}
	}
	return DBMetadata{
		Name:         sanitizeEvidence(rows[0][0]),
		UniqueName:   sanitizeEvidence(rows[0][1]),
		Version:      sanitizeEvidence(rows[0][2]),
		DatabaseRole: sanitizeEvidence(rows[0][3]),
		OpenMode:     sanitizeEvidence(rows[0][4]),
	}, nil
}
