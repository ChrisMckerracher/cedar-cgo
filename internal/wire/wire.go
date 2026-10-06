// Package wire mirrors the JSON contracts in rust/crates/abi and the operation crates.
package wire

import (
	"encoding/json/v2"
	"errors"
	"unicode/utf8"
)

// CheckUTF8 prevents JSON replacement from changing identities or source text.
func CheckUTF8(texts ...string) error {
	for _, text := range texts {
		if !utf8.ValidString(text) {
			return errors.New("input must be valid UTF-8")
		}
	}
	return nil
}

type Source struct {
	// Format is "cedar" or "json".
	Format string `json:"format"`
	Text   string `json:"text"`
}

func (s Source) MarshalJSON() ([]byte, error) {
	type source Source
	return json.Marshal(source(s))
}

type UID struct {
	Type string `json:"type"`
	ID   string `json:"id"`
}

func (u UID) MarshalJSON() ([]byte, error) {
	type uid UID
	return json.Marshal(uid(u))
}

type Error struct {
	Kind    string `json:"kind"`
	Message string `json:"message"`
}

type Response struct {
	Error *Error `json:"error"`
}

func (r Response) ResponseError() *Error { return r.Error }
