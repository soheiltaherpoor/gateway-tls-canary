// gateway-tls-canary pins the public keys of the TLS endpoints you depend on and
// reports when they change.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/soheiltaherpoor/gateway-tls-canary/internal/config"
	"github.com/soheiltaherpoor/gateway-tls-canary/internal/exporter"
	"github.com/soheiltaherpoor/gateway-tls-canary/internal/probe"
)

var version = "dev"

const usage = `gateway-tls-canary %s

Usage:
  gateway-tls-canary learn [-sni NAME] [-timeout 10s] HOST:PORT   show the chain and the pins to put in the config
  gateway-tls-canary check -config FILE [-json]                    probe once; exit 0 ok, 1 pin mismatch, 2 probe failed
  gateway-tls-canary serve -config FILE                            probe on a schedule and serve Prometheus metrics
  gateway-tls-canary version

Flags go before the positional argument.
`

const (
	exitOK       = 0
	exitMismatch = 1
	exitProbe    = 2
	exitUsage    = 3
)

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintf(stderr, usage, version)
		return exitUsage
	}
	var err error
	code := exitOK
	switch args[0] {
	case "learn":
		err = learn(args[1:], stdout)
	case "check":
		code, err = check(args[1:], stdout)
	case "serve":
		err = serve(args[1:], stderr)
	case "version":
		fmt.Fprintln(stdout, version)
	case "help", "-h", "--help":
		fmt.Fprintf(stdout, usage, version)
	default:
		fmt.Fprintf(stderr, "unknown command %q\n\n", args[0])
		fmt.Fprintf(stderr, usage, version)
		return exitUsage
	}
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitOK
		}
		fmt.Fprintln(stderr, "error:", err)
		return exitUsage
	}
	return code
}

func loadConfig(path string) (*config.Config, error) {
	if path == "" {
		return nil, errors.New("-config is required")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return config.Load(f)
}

func learn(args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("learn", flag.ContinueOnError)
	sni := fs.String("sni", "", "server name to send (default: the host part)")
	timeout := fs.Duration("timeout", 10*time.Second, "dial plus handshake timeout")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("learn needs exactly one HOST:PORT")
	}
	res, err := probe.Probe(context.Background(), fs.Arg(0), *sni, probe.Options{Timeout: *timeout})
	if err != nil {
		return err
	}
	fmt.Fprintf(stdout, "%s  %s\n", fs.Arg(0), res.TLSVersion)
	if res.ChainValid {
		fmt.Fprintln(stdout, "chain verifies against the system trust roots")
	} else {
		fmt.Fprintln(stdout, "chain does NOT verify:", res.ChainError)
	}
	for i, c := range res.Chain {
		role := "intermediate or root"
		if i == 0 {
			role = "leaf"
		}
		fmt.Fprintf(stdout, "\n[%d] %s\n    subject  %s\n    issuer   %s\n    expires  %s\n    pin      %s\n",
			i, role, c.Subject, c.Issuer, c.NotAfter.UTC().Format("2006-01-02"), c.Pin)
	}
	fmt.Fprintln(stdout, "\nPut one or more pins in the target's \"pins\" list. An intermediate CA pin survives")
	fmt.Fprintln(stdout, "leaf renewals; a leaf pin is stricter but must be updated whenever the key changes.")
	return nil
}

type checkRow struct {
	Target       string   `json:"target"`
	Status       string   `json:"status"` // ok, mismatch, error
	MatchedIndex *int     `json:"matched_index,omitempty"`
	ChainValid   *bool    `json:"chain_valid,omitempty"`
	NotAfter     string   `json:"not_after,omitempty"`
	Chain        []string `json:"chain_pins,omitempty"`
	Error        string   `json:"error,omitempty"`
}

func check(args []string, stdout io.Writer) (int, error) {
	fs := flag.NewFlagSet("check", flag.ContinueOnError)
	path := fs.String("config", "", "path to the JSON config")
	asJSON := fs.Bool("json", false, "machine-readable output")
	if err := fs.Parse(args); err != nil {
		return exitUsage, err
	}
	cfg, err := loadConfig(*path)
	if err != nil {
		return exitUsage, err
	}
	var rows []checkRow
	mismatch, failed := false, false
	for _, t := range cfg.Targets {
		res, perr := probe.Probe(context.Background(), t.Address, t.SNI, probe.Options{Timeout: cfg.Timeout})
		row := checkRow{Target: t.Name}
		switch {
		case perr != nil:
			row.Status, row.Error = "error", perr.Error()
			failed = true
		default:
			idx, ok := res.Matches(t.Pins)
			valid := res.ChainValid
			row.ChainValid = &valid
			row.NotAfter = res.Chain[0].NotAfter.UTC().Format("2006-01-02")
			if ok {
				row.Status, row.MatchedIndex = "ok", &idx
			} else {
				row.Status = "mismatch"
				mismatch = true
				for _, c := range res.Chain {
					row.Chain = append(row.Chain, c.Pin)
				}
			}
		}
		rows = append(rows, row)
	}
	if *asJSON {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(rows)
	} else {
		for _, r := range rows {
			switch r.Status {
			case "ok":
				fmt.Fprintf(stdout, "[ OK ] %s  pinned key found at chain position %d; chain valid: %v; leaf expires %s\n",
					r.Target, *r.MatchedIndex, *r.ChainValid, r.NotAfter)
			case "mismatch":
				fmt.Fprintf(stdout, "[FAIL] %s  PIN MISMATCH: no certificate in the presented chain has a pinned key (chain valid: %v)\n", r.Target, *r.ChainValid)
				for i, p := range r.Chain {
					fmt.Fprintf(stdout, "         [%d] %s\n", i, p)
				}
			default:
				fmt.Fprintf(stdout, "[ERR ] %s  %s\n", r.Target, r.Error)
			}
		}
	}
	switch {
	case mismatch:
		return exitMismatch, nil
	case failed:
		return exitProbe, nil
	}
	return exitOK, nil
}

func serve(args []string, stderr io.Writer) error {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	path := fs.String("config", "", "path to the JSON config")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, err := loadConfig(*path)
	if err != nil {
		return err
	}
	log := slog.New(slog.NewTextHandler(stderr, nil))
	fn := func(ctx context.Context, t config.Target) (*probe.Result, error) {
		return probe.Probe(ctx, t.Address, t.SNI, probe.Options{Timeout: cfg.Timeout})
	}
	exp := exporter.New(cfg, fn, log, nil)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go exp.Run(ctx)

	srv := &http.Server{Addr: cfg.Listen, Handler: exp.Handler(), ReadHeaderTimeout: 5 * time.Second}
	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(sctx)
	}()
	log.Info("listening", "addr", cfg.Listen, "targets", len(cfg.Targets), "interval", cfg.Interval.String(), "version", version)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}
