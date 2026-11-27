// Package config loads and validates the JSON configuration.
package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var (
	nameRE = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,64}$`)
	pinRE  = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
)

// Target is one endpoint to watch.
type Target struct {
	Name    string   `json:"name"`
	Address string   `json:"address"`
	SNI     string   `json:"sni"`
	Pins    []string `json:"pins"`
}

// Config is the validated configuration.
type Config struct {
	Listen   string
	Interval time.Duration
	Timeout  time.Duration
	Targets  []Target
}

type raw struct {
	Listen   string   `json:"listen"`
	Interval string   `json:"interval"`
	Timeout  string   `json:"timeout"`
	Targets  []Target `json:"targets"`
}

// Load reads a configuration, rejecting unknown fields.
func Load(r io.Reader) (*Config, error) {
	dec := json.NewDecoder(r)
	dec.DisallowUnknownFields()
	var in raw
	if err := dec.Decode(&in); err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	c := &Config{Listen: in.Listen, Interval: 5 * time.Minute, Timeout: 10 * time.Second, Targets: in.Targets}
	if c.Listen == "" {
		c.Listen = "127.0.0.1:9195"
	}
	var err error
	if in.Interval != "" {
		if c.Interval, err = time.ParseDuration(in.Interval); err != nil {
			return nil, fmt.Errorf("config: interval: %w", err)
		}
	}
	if in.Timeout != "" {
		if c.Timeout, err = time.ParseDuration(in.Timeout); err != nil {
			return nil, fmt.Errorf("config: timeout: %w", err)
		}
	}
	if c.Interval < 10*time.Second {
		return nil, errors.New("config: interval must be at least 10s")
	}
	if c.Timeout < time.Second || c.Timeout > c.Interval {
		return nil, errors.New("config: timeout must be between 1s and the interval")
	}
	if len(c.Targets) == 0 {
		return nil, errors.New("config: at least one target is required")
	}
	seen := map[string]bool{}
	for i := range c.Targets {
		t := &c.Targets[i]
		if !nameRE.MatchString(t.Name) {
			return nil, fmt.Errorf("config: target %d: name must be 1-64 characters of letters, digits, _ . -", i+1)
		}
		if seen[t.Name] {
			return nil, fmt.Errorf("config: duplicate target name %q", t.Name)
		}
		seen[t.Name] = true
		host, port, err := net.SplitHostPort(t.Address)
		if err != nil || host == "" {
			return nil, fmt.Errorf("config: target %q: address must be host:port", t.Name)
		}
		if p, err := strconv.Atoi(port); err != nil || p < 1 || p > 65535 {
			return nil, fmt.Errorf("config: target %q: invalid port", t.Name)
		}
		if len(t.Pins) == 0 {
			return nil, fmt.Errorf("config: target %q: at least one pin is required (use the learn command to get them)", t.Name)
		}
		for j, p := range t.Pins {
			p = strings.ToLower(strings.TrimSpace(p))
			if !pinRE.MatchString(p) {
				return nil, fmt.Errorf("config: target %q: pin %d must look like sha256:<64 hex characters>", t.Name, j+1)
			}
			t.Pins[j] = p
		}
	}
	return c, nil
}
