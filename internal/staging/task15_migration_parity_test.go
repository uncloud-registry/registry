package staging

// Frozen-parity holdings for the two v1 predecessor schemas. Each predecessor
// golden is bound to the EXACT historical DDL of the committed green state it
// represents (recovered from the git predecessor commit and frozen here), so a
// unilateral change to either a predecessor golden OR its frozen DDL breaks
// parity independently. The cleanup-token-v1 predecessor's object surface is
// additionally asserted to equal the current (v2) surface, which is exactly
// what makes that path a pure version advance.

import (
	_ "embed"
	"encoding/json"
	"reflect"
	"testing"
)

// Frozen historical DDL of the pre-cleanup-token v1 commit: the version-table
// DDL plus the ordered schemaDDL bodies it shipped. Independently frozen so it
// cannot drift silently with the production migration constants.
//
//go:embed schema_ddl_v1_precleanup.json
var schemaV1PreDDLJSON []byte

type frozenDDL struct {
	VersionTable string   `json:"version_table"`
	Objects      []string `json:"objects"`
}

// deriveFromFrozenDDL computes the manifest a generator WOULD produce from the
// frozen DDL bodies (object identities from the DDL, physical expectations
// from the frozen golden — the columns/indexes/FKs are the independently
// authored part and can only come from the golden itself).
func deriveFromFrozenDDL(gold *schemaManifest, versionTable string, ddl []string) *schemaManifest {
	m := &schemaManifest{Version: gold.Version}
	all := append([]string{versionTable}, ddl...)
	for _, body := range all {
		typ, name, tbl, err := parseDDLHead(body)
		if err != nil {
			return nil
		}
		norm, err := normalizeSQL(body)
		if err != nil {
			return nil
		}
		m.Objects = append(m.Objects, schemaObject{Typ: typ, Name: name, Tbl: tbl, SQL: norm})
	}
	m.Columns = gold.Columns
	m.Indexes = gold.Indexes
	m.ForeignKeys = gold.ForeignKeys
	return m
}

func TestSchemaGoldenParityV1PreCleanup(t *testing.T) {
	var frozen frozenDDL
	if err := json.Unmarshal(schemaV1PreDDLJSON, &frozen); err != nil {
		t.Fatalf("frozen v1-pre DDL not parseable: %v", err)
	}
	derived := deriveFromFrozenDDL(schemaGoldV1Pre, frozen.VersionTable, frozen.Objects)
	if derived == nil {
		t.Fatal("cannot derive a manifest from the frozen v1-pre DDL")
	}
	if len(derived.Objects) != len(schemaGoldV1Pre.Objects) {
		t.Fatalf("v1-pre derived objects = %d, golden = %d", len(derived.Objects), len(schemaGoldV1Pre.Objects))
	}
	if !reflect.DeepEqual(derived.Objects, schemaGoldV1Pre.Objects) {
		t.Fatal("v1-pre golden drifted from the frozen pre-cleanup DDL")
	}
	// DDL-solo change must fail parity.
	ddlMut := deriveFromFrozenDDL(schemaGoldV1Pre, frozen.VersionTable, frozen.Objects)
	ddlMut.Objects[1].SQL += " -- nudge"
	if reflect.DeepEqual(ddlMut.Objects, schemaGoldV1Pre.Objects) {
		t.Fatal("parity cannot detect a v1-pre DDL-only change")
	}
	// Golden-solo change must fail parity (clone before mutating the package
	// golden's slice).
	goldMut := *schemaGoldV1Pre
	goldMut.Objects = append([]schemaObject(nil), schemaGoldV1Pre.Objects...)
	goldMut.Objects[1].SQL += " -- nudge"
	if reflect.DeepEqual(&goldMut, derived) {
		t.Fatal("parity cannot detect a v1-pre golden-only change")
	}
}

func TestSchemaGoldenParityV1CleanupSharesV2Surface(t *testing.T) {
	// The cleanup-token-v1 predecessor shipped the SAME object bodies as v2
	// (that is exactly why its migration is a pure version advance). Both
	// frozen goldens must agree on the object surface, and both must match the
	// current production DDL-derived surface.
	if len(schemaGoldV1Cleanup.Objects) != len(schemaGold.Objects) {
		t.Fatalf("cleanup-v1 objects = %d, v2 objects = %d", len(schemaGoldV1Cleanup.Objects), len(schemaGold.Objects))
	}
	for i := range schemaGoldV1Cleanup.Objects {
		a, b := schemaGoldV1Cleanup.Objects[i], schemaGold.Objects[i]
		if a.Typ != b.Typ || a.Name != b.Name || a.Tbl != b.Tbl || a.SQL != b.SQL {
			t.Fatalf("cleanup-v1 predecessor object %d differs from the v2 surface: %+v vs %+v", i, a, b)
		}
	}
	derived := deriveFromDDL() // current production DDL-derived surface (v2)
	if derived == nil || !reflect.DeepEqual(derived.Objects, schemaGoldV1Cleanup.Objects) {
		t.Fatal("cleanup-token-v1 predecessor surface drifted from the production DDL")
	}
	// A golden-only change to the cleanup predecessor must fail parity.
	goldMut := *schemaGoldV1Cleanup
	goldMut.Objects = append([]schemaObject(nil), schemaGoldV1Cleanup.Objects...)
	goldMut.Objects[1].SQL += " -- nudge"
	if reflect.DeepEqual(&goldMut, derived) {
		t.Fatal("parity cannot detect a cleanup-v1 golden-only change")
	}
}
