// Package wire mirrors the JSON contracts in rust/crates/abi and the operation crates.
package wire

type Source struct {
	// Format is "cedar" or "json".
	Format string `json:"format"`
	Text   string `json:"text"`
}

type UID struct {
	Type string `json:"type"`
	ID   string `json:"id"`
}

type Error struct {
	Kind    string `json:"kind"`
	Message string `json:"message"`
}
