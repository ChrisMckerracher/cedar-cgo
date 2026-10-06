package generator

import (
	cedarvalue "github.com/ChrisMckerracher/cedar-cgo/cedar/value"
	rapid "pgregory.net/rapid"
)

// propUtilSchema declares exactly one fitting scope triple: User / Action::"view" / Photo.
const PropUtilSchema = `entity User; entity Photo; action "view" appliesTo { principal: User, resource: Photo, context: {} };`

// propUtilGenScalar draws the Cedar leaf values whose evaluated shape the merge
// oracle can rebuild exactly: Bool, Long, and String.
func PropUtilGenScalar() *rapid.Generator[cedarvalue.Value] {
	return rapid.OneOf(
		rapid.Map(rapid.Bool(), func(b bool) cedarvalue.Value { return cedarvalue.Bool(b) }),
		rapid.Map(rapid.Int64(), func(n int64) cedarvalue.Value { return cedarvalue.Long(n) }),
		rapid.Map(rapid.StringN(0, 8, 32), func(s string) cedarvalue.Value { return cedarvalue.String(s) }),
	)
}

// propUtilEvalOf narrows a drawn scalar to its evaluated shape; Bool, Long, and
// String are their own EvalResult variants.
func PropUtilEvalOf(value cedarvalue.Value) cedarvalue.EvalResult {
	switch scalar := value.(type) {
	case cedarvalue.Bool:
		return scalar
	case cedarvalue.Long:
		return scalar
	default:
		return scalar.(cedarvalue.String)
	}
}
