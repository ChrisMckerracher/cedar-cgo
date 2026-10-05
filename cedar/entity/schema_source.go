package entity

import (
	"github.com/ChrisMckerracher/cedar-go-wasm/internal/wire"
	"reflect"
)

type SchemaSource interface{ Wire() wire.Source }

func hasSchema(s SchemaSource) bool {
	return s != nil && !(reflect.ValueOf(s).Kind() == reflect.Pointer && reflect.ValueOf(s).IsNil())
}
