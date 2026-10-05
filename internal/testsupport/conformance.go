package testsupport

import (
	bytes "bytes"
	json "encoding/json"
	fmt "fmt"
	entityuid "github.com/ChrisMckerracher/cedar-go-wasm/cedar/entity/uid"
	cedarpolicy "github.com/ChrisMckerracher/cedar-go-wasm/cedar/policy"
	cedarschema "github.com/ChrisMckerracher/cedar-go-wasm/cedar/schema"
	sync "sync"
)

// Match cedar-testing's JsonTest so both implementations consume the same corpus.
type CorpusTest struct {
	Policies       string          `json:"policies"`
	PolicyFormat   string          `json:"policyFormat"`
	Entities       string          `json:"entities"`
	Schema         string          `json:"schema"`
	SchemaFormat   string          `json:"schemaFormat"`
	ShouldValidate bool            `json:"shouldValidate"`
	Requests       []CorpusRequest `json:"requests"`
}

type CorpusRequest struct {
	Description     string          `json:"description"`
	Principal       CorpusUID       `json:"principal"`
	Action          CorpusUID       `json:"action"`
	Resource        CorpusUID       `json:"resource"`
	Context         json.RawMessage `json:"context"`
	ValidateRequest *bool           `json:"validateRequest"`
	Decision        string          `json:"decision"`
	Reason          []string        `json:"reason"`
	Errors          []string        `json:"errors"`
}

// corpusUID accepts both entity reference forms that the corpus may use:
// {"type": ..., "id": ...} and {"__entity": {"type": ..., "id": ...}}.
type CorpusUID struct{ entityuid.EntityUID }

func (u *CorpusUID) UnmarshalJSON(b []byte) error {
	var v struct {
		Type   *string `json:"type"`
		ID     *string `json:"id"`
		Entity *struct {
			Type string `json:"type"`
			ID   string `json:"id"`
		} `json:"__entity"`
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&v); err != nil {
		return err
	}
	switch {
	case v.Entity != nil && v.Type == nil && v.ID == nil:
		u.EntityUID = entityuid.NewEntityUID(v.Entity.Type, v.Entity.ID)
	case v.Entity == nil && v.Type != nil && v.ID != nil:
		u.EntityUID = entityuid.NewEntityUID(*v.Type, *v.ID)
	default:
		return fmt.Errorf("unrecognized entity reference %s", b)
	}
	return nil
}

type CorpusTally struct {
	Mu                 sync.Mutex
	Tests, Requests    int
	DecisionMismatch   int
	ReasonMismatch     int
	ErrorMismatch      int
	ValidationMismatch int
	SetupFailure       int
	RequestFailure     int
	Examples           []string
}

func (c *CorpusTally) Note(counter *int, FormatValue string, args ...any) {
	c.Mu.Lock()
	defer c.Mu.Unlock()
	*counter++
	if len(c.Examples) < 50 {
		c.Examples = append(c.Examples, fmt.Sprintf(FormatValue, args...))
	}
}

func ParsePolicies(FormatValue, TextValue string) cedarpolicy.PolicySet {
	if FormatValue == "json" {
		return cedarpolicy.PoliciesFromJSON([]byte(TextValue))
	}
	return cedarpolicy.PoliciesFromCedar(TextValue)
}

func ParseSchema(FormatValue, TextValue string) cedarschema.Schema {
	if FormatValue == "json" {
		return cedarschema.SchemaFromJSON([]byte(TextValue))
	}
	return cedarschema.SchemaFromCedar(TextValue)
}
