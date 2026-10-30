package remotecode

import (
	"encoding/json"
	"fmt"
	"path"
	"regexp"
	"strings"
)

// override is a config field that makes a loader run code the caller did not
// agree to: the field is the evidence, whatever the code it names holds.
type override struct {
	pattern string
	where   string
	what    string
	detail  string
	fail    bool
}

// kernelRef is what transformers' is_kernel takes for a Hub kernel
// repository (integrations/hub_kernels.py, v4.57.6, v5.2.0, v5.19.0):
// owner/repo, with an optional @revision and :function.
var kernelRef = regexp.MustCompile(`^[^/:]+/[^/:]+(?:@[^/:]+)?(?::[^/:]+)?$`)

// curatedKernels is the one owner transformers 5.3.0 and later load a kernel
// from unless the caller allows others (get_kernel's allow_all_kernels).
const curatedKernels = "kernels-community"

// attnFields are the config keys that set a model's attention
// implementation from config.json. PreTrainedConfig.__init__ (v4.57.6,
// v5.2.0) applies every key it does not know with setattr: the internal field
// directly, and _attn_implementation through its property setter, which
// writes the internal field (and a sub-config's, from a dict). to_dict drops
// the internal field and never writes the property, so save_pretrained
// writes neither.
var attnFields = map[string]bool{"_attn_implementation_internal": true, "_attn_implementation": true}

// overrides reads the fields of one config.json, at any depth (a composite
// model builds each sub-config from its dict the same way), that make a
// loader run code without trust_remote_code.
func overrides(rel string, obj map[string]any) []override {
	if path.Base(rel) != "config.json" {
		return nil
	}
	var out []override
	var walk func(prefix string, v any, depth int)
	walk = func(prefix string, v any, depth int) {
		if depth > maxDepth || len(out) > maxRefsPerFile {
			return
		}
		switch x := v.(type) {
		case map[string]any:
			for _, k := range sortedKeys(x) {
				switch {
				case attnFields[k]:
					for _, leaf := range stringLeaves("", x[k], depth) {
						where := rel + ": " + prefix + k
						if leaf.key != "" {
							where += "." + leaf.key
						}
						if o, ok := kernelField(where, leaf.s); ok {
							out = append(out, o)
						}
					}
				case k == "trust_remote_code" && truthy(x[k]):
					out = append(out, trustField(rel+": "+prefix+k, x))
				}
				walk(prefix+k+".", x[k], depth+1)
			}
		case []any:
			for i, e := range x {
				walk(fmt.Sprintf("%s[%d].", strings.TrimSuffix(prefix, "."), i), e, depth+1)
			}
		}
	}
	walk("", obj, 0)
	return out
}

// kernelField judges an attention implementation that names a Hub kernel.
// transformers 4.56.0 to 5.2.x load any owner's kernel (CVE-2026-4372);
// 5.3.0 and later load only kernels-community's unless told otherwise. A
// value after "paged|" is the kernel the paged wrapper loads.
func kernelField(where, value string) (override, bool) {
	name := strings.TrimSpace(value)
	if i := strings.LastIndex(name, "|"); i >= 0 {
		name = name[i+1:]
	}
	if !kernelRef.MatchString(name) {
		return override{}, false // eager, sdpa, flash_attention_2: the library's own
	}
	owner := name[:strings.Index(name, "/")]
	if owner == curatedKernels {
		return override{pattern: "config-hub-kernel", where: where, what: value,
			detail: "names a kernels-community Hub kernel, which transformers 4.56.0 and later download and run when the model loads, " +
				"without trust_remote_code; save_pretrained never writes this field"}, true
	}
	return override{pattern: "config-kernel-injection", where: where, what: value, fail: true,
		detail: "names a Hub kernel from " + owner + ", which transformers 4.56.0 to 5.2.x download and run when the model loads, " +
			"with trust_remote_code=False, once the kernels package is installed (CVE-2026-4372, fixed in 5.3.0); " +
			"save_pretrained never writes this field"}, true
}

// trustField is a config that grants its own loader trust_remote_code.
// transformers' LightGlue config read it before 5.5.0 and passed it to the
// AutoConfig.from_pretrained that loads its keypoint detector from the
// repository keypoint_detector_config._name_or_path names, which imports that
// repository's code when the caller had set trust_remote_code=False
// (CVE-2026-5241). Other loaders ignore the key, so it is a LEAD.
func trustField(where string, obj map[string]any) override {
	what := "trust_remote_code: " + jsonText(obj["trust_remote_code"])
	if kd, ok := obj["keypoint_detector_config"].(map[string]any); ok {
		if s, ok := kd["_name_or_path"].(string); ok && s != "" {
			what += ", keypoint_detector_config._name_or_path: " + s
		}
	}
	return override{pattern: "config-trust-remote-code", where: where, what: what,
		detail: "a config that grants its own loader trust_remote_code: transformers before 5.5.0 passed LightGlue's to the " +
			"AutoConfig.from_pretrained that loads its keypoint detector, importing another repository's code with " +
			"trust_remote_code=False (CVE-2026-5241)"}
}

// truthy is Python's truth value of a decoded JSON value.
func truthy(v any) bool {
	switch x := v.(type) {
	case nil:
		return false
	case bool:
		return x
	case float64:
		return x != 0
	case string:
		return x != ""
	case []any:
		return len(x) > 0
	case map[string]any:
		return len(x) > 0
	}
	return true
}

func jsonText(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return fmt.Sprint(v)
	}
	return string(b)
}
