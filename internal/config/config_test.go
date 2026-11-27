package config

import (
	"strings"
	"testing"
	"time"
)

var pin = "sha256:" + strings.Repeat("ab", 32)

func target(extra string) string {
	return `{"targets":[{"name":"gw","address":"gateway.example.com:443","pins":["` + pin + `"]}]` + extra + `}`
}

func TestValidWithDefaults(t *testing.T) {
	c, err := Load(strings.NewReader(target("")))
	if err != nil {
		t.Fatal(err)
	}
	if c.Listen != "127.0.0.1:9195" || c.Interval != 5*time.Minute || c.Timeout != 10*time.Second {
		t.Errorf("defaults: %+v", c)
	}
	if len(c.Targets) != 1 || c.Targets[0].Pins[0] != pin {
		t.Errorf("targets: %+v", c.Targets)
	}
}

func TestPinsAreNormalised(t *testing.T) {
	in := `{"targets":[{"name":"gw","address":"h:443","pins":[" SHA256:` + strings.Repeat("AB", 32) + ` "]}]}`
	c, err := Load(strings.NewReader(in))
	if err != nil {
		t.Fatal(err)
	}
	if c.Targets[0].Pins[0] != pin {
		t.Errorf("got %q", c.Targets[0].Pins[0])
	}
}

func TestExplicitSettings(t *testing.T) {
	c, err := Load(strings.NewReader(target(`,"listen":":9195","interval":"1m","timeout":"5s"`)))
	if err != nil {
		t.Fatal(err)
	}
	if c.Listen != ":9195" || c.Interval != time.Minute || c.Timeout != 5*time.Second {
		t.Errorf("%+v", c)
	}
}

func TestErrors(t *testing.T) {
	mk := func(tgt string) string { return `{"targets":[` + tgt + `]}` }
	good := `"name":"gw","address":"h:443","pins":["` + pin + `"]`
	cases := []struct{ name, in, want string }{
		{"bad json", `{`, "config:"},
		{"unknown field", target(`,"intervall":"1m"`), "unknown field"},
		{"no targets", `{"targets":[]}`, "at least one target"},
		{"bad interval", target(`,"interval":"soon"`), "interval"},
		{"short interval", target(`,"interval":"1s"`), "at least 10s"},
		{"timeout above interval", target(`,"interval":"20s","timeout":"30s"`), "timeout"},
		{"bad name", mk(`{"name":"a b","address":"h:443","pins":["` + pin + `"]}`), "name must be"},
		{"duplicate name", mk(`{` + good + `},{` + good + `}`), "duplicate"},
		{"no port", mk(`{"name":"gw","address":"example.com","pins":["` + pin + `"]}`), "host:port"},
		{"bad port", mk(`{"name":"gw","address":"h:99999","pins":["` + pin + `"]}`), "port"},
		{"no pins", mk(`{"name":"gw","address":"h:443","pins":[]}`), "at least one pin"},
		{"bad pin", mk(`{"name":"gw","address":"h:443","pins":["sha256:abc"]}`), "sha256:<64 hex"},
		{"pin without prefix", mk(`{"name":"gw","address":"h:443","pins":["` + strings.Repeat("ab", 32) + `"]}`), "sha256:<64 hex"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Load(strings.NewReader(tc.in))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want containing %q", err, tc.want)
			}
		})
	}
}
