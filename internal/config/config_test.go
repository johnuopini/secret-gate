package config

import (
	"testing"
	"time"
)

func TestLoad_SessionTTL(t *testing.T) {
	cases := []struct {
		name string
		env  string
		set  bool
		want time.Duration
	}{
		{name: "defaults to eight hours", want: 8 * time.Hour},
		{name: "reads a duration", env: "30m", set: true, want: 30 * time.Minute},
		{name: "zero turns the window off", env: "0", set: true, want: 0},
		{name: "a negative value turns the window off", env: "-1h", set: true, want: 0},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.set {
				t.Setenv("SESSION_TTL", tc.env)
			}

			cfg, err := Load()
			if err != nil {
				t.Fatalf("Load: %v", err)
			}
			if cfg.SessionTTL != tc.want {
				t.Errorf("SessionTTL = %s, want %s", cfg.SessionTTL, tc.want)
			}
		})
	}
}

func TestLoad_RejectsAnUnreadableSessionTTL(t *testing.T) {
	// Falling back to the default here would open an 8h window for someone
	// who tried to switch it off with a value like "off".
	t.Setenv("SESSION_TTL", "off")

	if _, err := Load(); err == nil {
		t.Fatal("Load accepted SESSION_TTL=off")
	}
}
