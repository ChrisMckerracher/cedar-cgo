package slicing

import "github.com/ChrisMckerracher/cedar-go-wasm/internal/execution"

// Client permits concurrent calls. Runtime.Close invalidates this client.
// Active native calls keep their resources until Cedar returns.
type Client struct{ runtime *execution.Runtime }

func New(rt *execution.Runtime) *Client { return &Client{runtime: rt} }
