package daemon

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"time"
)

type Client struct {
	socketPath string
}

func NewClient(socketPath string) *Client {
	return &Client{socketPath: socketPath}
}

func (c *Client) IsRunning() bool {
	conn, err := net.DialTimeout("unix", c.socketPath, 1*time.Second)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

func (c *Client) send(req Request) (*Response, error) {
	conn, err := net.DialTimeout("unix", c.socketPath, 2*time.Second)
	if err != nil {
		return nil, fmt.Errorf("connecting to daemon: %w", err)
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(5 * time.Second))

	data, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("marshaling request: %w", err)
	}
	data = append(data, '\n')

	if _, err := conn.Write(data); err != nil {
		return nil, fmt.Errorf("writing request: %w", err)
	}

	scanner := bufio.NewScanner(conn)
	if !scanner.Scan() {
		if err := scanner.Err(); err != nil {
			return nil, fmt.Errorf("reading response: %w", err)
		}
		return nil, fmt.Errorf("no response from daemon")
	}

	var resp Response
	if err := json.Unmarshal(scanner.Bytes(), &resp); err != nil {
		return nil, fmt.Errorf("parsing response: %w", err)
	}

	return &resp, nil
}

func (c *Client) Get(secretName, vault string) (map[string]string, error) {
	resp, err := c.send(Request{
		Command:    CmdGet,
		SecretName: secretName,
		Vault:      vault,
	})
	if err != nil {
		return nil, err
	}
	if !resp.OK {
		return nil, fmt.Errorf("%s", resp.Error)
	}
	return resp.Fields, nil
}

func (c *Client) Store(secretName, vault string, fields map[string]string, ttlSeconds int) error {
	resp, err := c.send(Request{
		Command:    CmdStore,
		SecretName: secretName,
		Vault:      vault,
		Fields:     fields,
		TTLSeconds: ttlSeconds,
	})
	if err != nil {
		return err
	}
	if !resp.OK {
		return fmt.Errorf("%s", resp.Error)
	}
	return nil
}

func (c *Client) Status() (*DaemonStatus, error) {
	resp, err := c.send(Request{Command: CmdStatus})
	if err != nil {
		return nil, err
	}
	if !resp.OK {
		return nil, fmt.Errorf("%s", resp.Error)
	}
	return resp.Status, nil
}

func (c *Client) List() ([]CacheEntryInfo, error) {
	resp, err := c.send(Request{Command: CmdList})
	if err != nil {
		return nil, err
	}
	if !resp.OK {
		return nil, fmt.Errorf("%s", resp.Error)
	}
	return resp.Entries, nil
}

func (c *Client) Flush() error {
	resp, err := c.send(Request{Command: CmdFlush})
	if err != nil {
		return err
	}
	if !resp.OK {
		return fmt.Errorf("%s", resp.Error)
	}
	return nil
}

func (c *Client) StopDaemon() error {
	resp, err := c.send(Request{Command: CmdStop})
	if err != nil {
		return err
	}
	if !resp.OK {
		return fmt.Errorf("%s", resp.Error)
	}
	return nil
}
