package daemon

import (
	"testing"
	"time"
)

func TestCacheStoreAndGet(t *testing.T) {
	c := NewCache()
	fields := map[string]string{"password": "secret123", "username": "admin"}
	c.Store("my-secret", "vault1", fields, 1*time.Hour)

	entry, ok := c.Get("my-secret", "vault1")
	if !ok {
		t.Fatal("expected cache hit")
	}
	if entry.Fields["password"] != "secret123" {
		t.Errorf("password = %q, want secret123", entry.Fields["password"])
	}
	if entry.Fields["username"] != "admin" {
		t.Errorf("username = %q, want admin", entry.Fields["username"])
	}
}

func TestCacheExpiry(t *testing.T) {
	c := NewCache()
	c.Store("my-secret", "vault1", map[string]string{"key": "val"}, 1*time.Millisecond)
	time.Sleep(5 * time.Millisecond)
	_, ok := c.Get("my-secret", "vault1")
	if ok {
		t.Error("expected cache miss after expiry")
	}
}

func TestCacheFlush(t *testing.T) {
	c := NewCache()
	c.Store("s1", "v1", map[string]string{"a": "1"}, 1*time.Hour)
	c.Store("s2", "v2", map[string]string{"b": "2"}, 1*time.Hour)
	if c.Count() != 2 {
		t.Errorf("Count = %d, want 2", c.Count())
	}
	c.Flush()
	if c.Count() != 0 {
		t.Errorf("Count after flush = %d, want 0", c.Count())
	}
}

func TestCacheList(t *testing.T) {
	c := NewCache()
	c.Store("s1", "v1", map[string]string{"a": "1"}, 1*time.Hour)
	c.Store("s2", "v2", map[string]string{"b": "2"}, 1*time.Hour)
	entries := c.List()
	if len(entries) != 2 {
		t.Errorf("List len = %d, want 2", len(entries))
	}
}

func TestCacheCleanup(t *testing.T) {
	c := NewCache()
	c.Store("expired", "v1", map[string]string{"a": "1"}, 1*time.Millisecond)
	c.Store("valid", "v2", map[string]string{"b": "2"}, 1*time.Hour)
	time.Sleep(5 * time.Millisecond)
	removed := c.Cleanup()
	if removed != 1 {
		t.Errorf("Cleanup removed = %d, want 1", removed)
	}
	if c.Count() != 1 {
		t.Errorf("Count after cleanup = %d, want 1", c.Count())
	}
}

func TestCacheOverwrite(t *testing.T) {
	c := NewCache()
	c.Store("s1", "v1", map[string]string{"a": "old"}, 1*time.Hour)
	c.Store("s1", "v1", map[string]string{"a": "new"}, 1*time.Hour)
	entry, ok := c.Get("s1", "v1")
	if !ok {
		t.Fatal("expected cache hit")
	}
	if entry.Fields["a"] != "new" {
		t.Errorf("field a = %q, want new", entry.Fields["a"])
	}
	if c.Count() != 1 {
		t.Errorf("Count = %d, want 1 (overwrite, not duplicate)", c.Count())
	}
}

func TestCacheHasValidEntries(t *testing.T) {
	c := NewCache()
	if c.HasValidEntries() {
		t.Error("empty cache should not have valid entries")
	}
	c.Store("s1", "v1", map[string]string{"a": "1"}, 1*time.Hour)
	if !c.HasValidEntries() {
		t.Error("cache with valid entry should have valid entries")
	}
}
