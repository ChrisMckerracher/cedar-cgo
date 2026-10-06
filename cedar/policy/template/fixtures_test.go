package template_test

import (
	bytes "bytes"
	json "encoding/json"
	request "github.com/ChrisMckerracher/cedar-cgo/cedar/authorization/request"
	diagnostic "github.com/ChrisMckerracher/cedar-cgo/cedar/diagnostic"
	entityuid "github.com/ChrisMckerracher/cedar-cgo/cedar/entity/uid"
	template "github.com/ChrisMckerracher/cedar-cgo/cedar/policy/template"
	reflect "reflect"
	sort "sort"
	testing "testing"
)

const ShareTemplate = `@description("shared access") permit(principal == ?principal, action == Action::"view", resource == ?resource);`

const TemplateSchema = `entity User; entity Photo; action view appliesTo { principal: User, resource: Photo, context: {} };`

func ShareBindings() template.SlotBindings {
	return template.SlotBindings{
		template.PrincipalSlot: entityuid.NewEntityUID("User", "alice"),
		template.ResourceSlot:  entityuid.NewEntityUID("Photo", "beach"),
	}
}

func TemplateRequest() request.Request {
	return request.Request{Principal: entityuid.NewEntityUID("User", "alice"), Action: entityuid.NewEntityUID("Action", "view"), Resource: entityuid.NewEntityUID("Photo", "beach")}
}

func NormalizedPolicyJSON(t testing.TB, data []byte) any {
	t.Helper()
	var value map[string]any
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := decoder.Decode(&value); err != nil {
		t.Fatal(err)
	}
	if links, ok := value["templateLinks"].([]any); ok {
		sort.Slice(links, func(i, j int) bool {
			a, _ := json.Marshal(links[i])
			b, _ := json.Marshal(links[j])
			return string(a) < string(b)
		})
	}
	return value
}

func EqualTemplateMessages(a, b []diagnostic.PolicyMessage) bool {
	sort.Slice(a, func(i, j int) bool {
		if a[i].PolicyID != a[j].PolicyID {
			return a[i].PolicyID < a[j].PolicyID
		}
		return a[i].Message < a[j].Message
	})
	sort.Slice(b, func(i, j int) bool {
		if b[i].PolicyID != b[j].PolicyID {
			return b[i].PolicyID < b[j].PolicyID
		}
		return b[i].Message < b[j].Message
	})
	return reflect.DeepEqual(a, b)
}
