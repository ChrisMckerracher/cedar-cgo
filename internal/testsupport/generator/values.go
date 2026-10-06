package generator

import (
	json "encoding/json"
	request "github.com/ChrisMckerracher/cedar-cgo/cedar/authorization/request"
	cedarentity "github.com/ChrisMckerracher/cedar-cgo/cedar/entity"
	entityuid "github.com/ChrisMckerracher/cedar-cgo/cedar/entity/uid"
	cedarvalue "github.com/ChrisMckerracher/cedar-cgo/cedar/value"
	rapid "pgregory.net/rapid"
)

// IDs come from an escape-free alphabet so generated Cedar text needs no quoting care.
// The x-prefix namespace cannot collide with Joy fixture IDs like phone1 or s1.
var (
	PropSafeID     = rapid.StringMatching(`x[a-z0-9]{0,7}`)
	PropJoyActions = []string{"session.read", "session.write", "terminal.open", "file.read", "file.write"}
	PropJoyDevices = []string{"phone1", "phone2", "tab1"}
	PropJoySess    = []string{"s1", "s2"}
	PropJoyProj    = []string{"proj0", "proj1", "proj7"}
	PropJoyAcct    = []string{"acct0", "acct1", "acct9"}
)

func PropGenPolicyID() *rapid.Generator[string] { return PropSafeID }

func PropGenDeviceUID() *rapid.Generator[entityuid.EntityUID] {
	return rapid.Map(PropSafeID, func(id string) entityuid.EntityUID { return entityuid.NewEntityUID("Joy::Device", id) })
}

var PropLeafKinds = []string{"bool", "long", "string", "decimal", "ip", "datetime", "duration", "uid", "set", "record"}

// propGenValue draws Cedar-shaped JSON values with valid extension literals.
func PropGenValue(depth int) *rapid.Generator[cedarvalue.Value] {
	return rapid.Custom(func(t *rapid.T) cedarvalue.Value {
		kind := rapid.SampledFrom(PropLeafKinds).Draw(t, "kind")
		if depth > 0 && kind == "set" {
			return cedarvalue.Set(rapid.SliceOfN(PropGenValue(depth-1), 0, 3).Draw(t, "set"))
		}
		if depth > 0 && kind == "record" {
			keys := rapid.SliceOfNDistinct(rapid.SampledFrom([]string{"a", "b", "c", "d"}), 0, 3, func(k string) string { return k }).Draw(t, "keys")
			record := cedarvalue.Record{}
			for _, k := range keys {
				record[k] = PropGenValue(depth-1).Draw(t, "value")
			}
			return record
		}
		switch kind {
		case "bool":
			return cedarvalue.Bool(rapid.Bool().Draw(t, "bool"))
		case "long":
			return cedarvalue.Long(rapid.Int64Range(-1000, 1000).Draw(t, "long"))
		case "string":
			return cedarvalue.String(rapid.StringN(0, 8, 32).Draw(t, "string"))
		case "decimal":
			return cedarvalue.Decimal(rapid.SampledFrom([]string{"1.5", "-0.99"}).Draw(t, "decimal"))
		case "ip":
			return cedarvalue.IPAddr(rapid.SampledFrom([]string{"10.1.2.3", "2001:db8::1"}).Draw(t, "ip"))
		case "datetime":
			return cedarvalue.Datetime(rapid.SampledFrom([]string{"2026-10-01T12:00:00Z", "1999-01-02T03:04:05Z"}).Draw(t, "datetime"))
		case "duration":
			return cedarvalue.Duration(rapid.SampledFrom([]string{"1h30m", "23h"}).Draw(t, "duration"))
		default:
			return cedarvalue.EntityRef(PropGenDeviceUID().Draw(t, "uid"))
		}
	})
}

// propGenContext draws a record matching Joy::Ctx so schema-checked requests accept it.
func PropGenContext() *rapid.Generator[request.Context] {
	return rapid.Custom(func(t *rapid.T) request.Context {
		return request.NewContext(cedarvalue.Record{
			"deviceLevel": cedarvalue.Long(int64(rapid.IntRange(0, 3).Draw(t, "deviceLevel"))),
			"platform": cedarvalue.Record{
				"os":            cedarvalue.String(rapid.SampledFrom([]string{"ios", "android"}).Draw(t, "os")),
				"model":         cedarvalue.String(rapid.StringMatching(`[A-Za-z0-9,]{0,10}`).Draw(t, "model")),
				"securityLevel": cedarvalue.Long(int64(rapid.IntRange(0, 4).Draw(t, "securityLevel"))),
			},
			"sessionId":       cedarvalue.String(rapid.StringMatching(`s[0-9]{0,3}`).Draw(t, "sessionId")),
			"now":             cedarvalue.Datetime(rapid.SampledFrom([]string{"2026-10-01T12:00:00Z", "2026-10-02T23:30:00Z"}).Draw(t, "now")),
			"machineAttested": cedarvalue.Bool(rapid.Bool().Draw(t, "machineAttested")),
			"sourceIp":        cedarvalue.IPAddr(rapid.SampledFrom([]string{"10.1.2.3", "127.0.0.1", "192.168.1.5"}).Draw(t, "sourceIp")),
		})
	})
}

// propGenRequest draws schema-valid Joy requests with concrete UIDs and a full Ctx.
func PropGenRequest() *rapid.Generator[request.Request] {
	return rapid.Custom(func(t *rapid.T) request.Request {
		return request.Request{
			Principal: entityuid.NewEntityUID("Joy::Device", PropGenPolicyID().Draw(t, "device")),
			Action:    entityuid.NewEntityUID("Joy::Action", rapid.SampledFrom(PropJoyActions).Draw(t, "action")),
			Resource:  entityuid.NewEntityUID("Joy::Session", PropGenPolicyID().Draw(t, "session")),
			Context:   PropGenContext().Draw(t, "context"),
		}
	})
}

// propGenExtraEntities draws standalone entities disjoint from the Joy fixtures
// with complete parent chains, safe to augment any preloaded store.
func PropGenExtraEntities() *rapid.Generator[cedarentity.Entities] {
	return rapid.Custom(func(t *rapid.T) cedarentity.Entities {
		accounts := []string{"xacct0", "xacct9"}
		extras := []cedarentity.Entity{
			{UID: entityuid.NewEntityUID("Joy::Account", accounts[0]), Attrs: cedarvalue.Record{}},
			{UID: entityuid.NewEntityUID("Joy::Account", accounts[1]), Attrs: cedarvalue.Record{}},
		}
		// Device declares no attributes in the Joy schema, so extras carry none.
		for _, id := range rapid.SliceOfNDistinct(PropGenPolicyID(), 0, 3, func(id string) string { return id }).Draw(t, "extraDevices") {
			extras = append(extras, cedarentity.Entity{
				UID:     entityuid.NewEntityUID("Joy::Device", id),
				Attrs:   cedarvalue.Record{},
				Parents: []entityuid.EntityUID{entityuid.NewEntityUID("Joy::Account", rapid.SampledFrom(accounts).Draw(t, "acct"))},
			})
		}
		return cedarentity.NewEntities(extras...)
	})
}

type PropEntityStore struct {
	Entities cedarentity.Entities
	Entries  []json.RawMessage
	Index    map[entityuid.EntityUID]int
}
