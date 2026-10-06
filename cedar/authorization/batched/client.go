package batched

import "github.com/ChrisMckerracher/cedar-cgo/internal/execution"

// Client permits concurrent calls. Runtime.Close invalidates this client.
// Active native calls keep their resources until Cedar returns.
type Client struct{ session *execution.Session }

func New(s *execution.Session) *Client { return &Client{session: s} }
