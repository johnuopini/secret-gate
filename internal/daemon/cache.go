package daemon

import (
	"fmt"
	"sync"
	"time"
)

type CacheEntry struct {
	SecretName  string
	Vault       string
	Fields      map[string]string
	CachedAt    time.Time
	ExpiresAt   time.Time
	SSHKeyAdded bool
}

type CacheEntryInfo struct {
	SecretName string    `json:"secret_name"`
	Vault      string    `json:"vault"`
	CachedAt   time.Time `json:"cached_at"`
	ExpiresAt  time.Time `json:"expires_at"`
}

func (e *CacheEntry) IsExpired() bool {
	return time.Now().After(e.ExpiresAt)
}

func (e *CacheEntry) RemainingTTL() time.Duration {
	remaining := time.Until(e.ExpiresAt)
	if remaining < 0 {
		return 0
	}
	return remaining
}

type Cache struct {
	mu      sync.RWMutex
	entries map[string]*CacheEntry
}

func NewCache() *Cache {
	return &Cache{
		entries: make(map[string]*CacheEntry),
	}
}

func cacheKey(secretName, vault string) string {
	return fmt.Sprintf("%s:%s", secretName, vault)
}

func (c *Cache) Store(secretName, vault string, fields map[string]string, ttl time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := time.Now()
	c.entries[cacheKey(secretName, vault)] = &CacheEntry{
		SecretName: secretName,
		Vault:      vault,
		Fields:     fields,
		CachedAt:   now,
		ExpiresAt:  now.Add(ttl),
	}
}

func (c *Cache) Get(secretName, vault string) (*CacheEntry, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	entry, ok := c.entries[cacheKey(secretName, vault)]
	if !ok || entry.IsExpired() {
		return nil, false
	}
	return entry, true
}

func (c *Cache) MarkSSHKeyAdded(secretName, vault string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if entry, ok := c.entries[cacheKey(secretName, vault)]; ok {
		entry.SSHKeyAdded = true
	}
}

func (c *Cache) Flush() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries = make(map[string]*CacheEntry)
}

func (c *Cache) Count() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.entries)
}

func (c *Cache) Cleanup() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	removed := 0
	for key, entry := range c.entries {
		if entry.IsExpired() {
			delete(c.entries, key)
			removed++
		}
	}
	return removed
}

func (c *Cache) List() []CacheEntryInfo {
	c.mu.RLock()
	defer c.mu.RUnlock()
	var list []CacheEntryInfo
	for _, entry := range c.entries {
		if !entry.IsExpired() {
			list = append(list, CacheEntryInfo{
				SecretName: entry.SecretName,
				Vault:      entry.Vault,
				CachedAt:   entry.CachedAt,
				ExpiresAt:  entry.ExpiresAt,
			})
		}
	}
	return list
}

func (c *Cache) HasValidEntries() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	for _, entry := range c.entries {
		if !entry.IsExpired() {
			return true
		}
	}
	return false
}
