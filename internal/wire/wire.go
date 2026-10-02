// Package wire defines the JSON types that cross the boundary between the
// Go host and the guest modules. rust/crates/abi and the operation crates
// define the same shapes on the guest side.
package wire

// Source is a schema or a policy set as source text.
type Source struct {
	// Format is "cedar" or "json".
	Format string `json:"format"`
	Text   string `json:"text"`
}

// UID is an entity UID in Cedar's {"type", "id"} JSON form.
type UID struct {
	Type string `json:"type"`
	ID   string `json:"id"`
}

// Error is the body of a failed operation's response.
type Error struct {
	Kind    string `json:"kind"`
	Message string `json:"message"`
}
