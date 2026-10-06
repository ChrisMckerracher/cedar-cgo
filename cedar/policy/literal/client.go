package literal

import "github.com/ChrisMckerracher/cedar-cgo/internal/execution"

// Client permits concurrent calls. Runtime.Close invalidates this client.
type Client struct{ runtime *execution.Runtime }

func New(rt *execution.Runtime) *Client { return &Client{runtime: rt} }
