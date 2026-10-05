package syntax

type Format int

const (
	// FormatCedar selects Cedar's human-readable syntax.
	FormatCedar Format = iota
	FormatJSON
)

func (f Format) Wire() string {
	if f == FormatJSON {
		return "json"
	}
	return "cedar"
}

func (f Format) String() string { return f.Wire() }
