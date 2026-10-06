// Package query enumerates permissions through the loaded authorization session.
package query

import "github.com/ChrisMckerracher/cedar-go-wasm/internal/execution"

// Client shares its originating authorizer's lifetime and request limits.
type Client struct{ session *execution.Session }

func New(session *execution.Session) *Client { return &Client{session: session} }
