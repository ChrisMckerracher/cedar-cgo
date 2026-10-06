package partial

// PartialDecision is experimental. Its zero value grants no permission.
type PartialDecision int

const (
	Undecided PartialDecision = iota
	PartialDeny
	PartialAllow
)

func (d PartialDecision) String() string {
	switch d {
	case PartialDeny:
		return "deny"
	case PartialAllow:
		return "allow"
	default:
		return "undecided"
	}
}
