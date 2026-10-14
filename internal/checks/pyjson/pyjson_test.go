package pyjson

import "testing"

// TestPythonConstants: NaN, Infinity, and -Infinity outside strings decode,
// as Python's json.loads reads them; inside strings they are text, and
// anything else that is not JSON still fails. Falsification: decode with
// encoding/json alone and the first cases fail.
func TestPythonConstants(t *testing.T) {
	var v map[string]any
	if err := Unmarshal([]byte(`{"a": NaN, "b": Infinity, "c": -Infinity, "d": [NaN, 1], "e": 2}`), &v); err != nil {
		t.Fatal(err)
	}
	if v["a"] != nil || v["b"] != nil || v["c"] != nil || v["e"] != float64(2) {
		t.Fatalf("decoded as %v", v)
	}
	if err := Unmarshal([]byte(`{"s": "NaN and Infinity, \"-Infinity\" too", "t": "\\"}`), &v); err != nil {
		t.Fatal(err)
	}
	if v["s"] != `NaN and Infinity, "-Infinity" too` || v["t"] != `\` {
		t.Fatalf("strings changed: %q %q", v["s"], v["t"])
	}
	var c struct {
		Arch  []string `json:"architectures"`
		Scale float64  `json:"scale"`
	}
	if err := Unmarshal([]byte(`{"architectures": ["NemotronHForCausalLM"], "scale": Infinity}`), &c); err != nil || c.Arch[0] != "NemotronHForCausalLM" {
		t.Fatalf("a struct with an Infinity field: %v %+v", err, c)
	}
	for _, bad := range []string{`{"a": nan}`, `{"a": inf}`, `{"a": NaN`, `{"a": 1} trailing`, `{"a": Infinite}`} {
		if err := Unmarshal([]byte(bad), &v); err == nil {
			t.Errorf("%s decoded", bad)
		}
	}
}
