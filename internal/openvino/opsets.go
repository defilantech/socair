package openvino

import (
	_ "embed"
	"strings"
)

// opsetsTable is OpenVINO 2026.4.1's opset1 to opset17, written by opsetgen.
//
//go:embed opsets.txt
var opsetsTable string

// opsets maps an opset name to its operations, upper-cased: the IR reader
// looks a type up ignoring ASCII case (OpSet::to_upper_name).
var opsets = parseOpsets(opsetsTable)

func parseOpsets(table string) map[string]map[string]bool {
	out := map[string]map[string]bool{}
	for _, line := range strings.Split(table, "\n") {
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		f := strings.Fields(line)
		ops := map[string]bool{}
		for _, op := range f[1:] {
			ops[asciiUpper(op)] = true
		}
		out[f[0]] = ops
	}
	return out
}

// Opsets lists the opset names the IR reader knows, in order.
func Opsets() []string {
	var out []string
	for _, line := range strings.Split(opsetsTable, "\n") {
		if line != "" && !strings.HasPrefix(line, "#") {
			out = append(out, strings.Fields(line)[0])
		}
	}
	return out
}

// experimentalOps are the operations the IR reader builds from opset6 when
// a layer's version is "experimental" or "extension"
// (experimental_ops_added_to_opset in XmlDeserializer::create_node).
var experimentalOps = map[string]bool{
	"ExperimentalDetectronDetectionOutput": true, "ExperimentalDetectronGenerateProposalsSingleImage": true,
	"ExperimentalDetectronPriorGridGenerator": true, "ExperimentalDetectronROIFeatureExtractor": true,
	"ExperimentalDetectronTopKROIs": true, "GRUCell": true, "RNNCell": true, "Proposal": true,
}

// opset1Moved are the operations the IR reader builds from opset2 when a
// layer names opset1, which lacked them.
var opset1Moved = map[string]bool{"MVN": true, "ROIPooling": true, "ReorgYolo": true}

// typeName translates an IR type to the operation's name, as the IR reader
// does before it looks one up (translate_type_name in
// xml_deserialize_util.cpp). Only exact spellings are translated.
func typeName(typ string) string {
	switch typ {
	case "Const":
		return "Constant"
	case "PReLU":
		return "PRelu"
	case "ReLU":
		return "Relu"
	case "SoftMax":
		return "Softmax"
	}
	return typ
}

// Standard reports whether OpenVINO 2026.4.1's IR reader builds a layer of
// this type and version from its own opsets, with no extension registered,
// and the opset it builds it from. Anything else it builds only from an
// extension the deployment registers for that type and version.
func Standard(version, typ string) (string, bool) {
	name := typeName(typ)
	set := version
	switch {
	case experimentalOps[name] && (version == "experimental" || version == "extension"):
		set = "opset6"
	case version == "opset1" && opset1Moved[name]:
		set = "opset2"
	}
	ops, ok := opsets[set]
	if !ok {
		return set, false
	}
	return set, ops[asciiUpper(name)]
}

// isOp reports whether a layer of this type and version is the standard
// operation op (an upper-cased name), as the reader would build it.
func isOp(version, typ, op string) bool {
	if _, ok := Standard(version, typ); !ok {
		return false
	}
	return asciiUpper(typeName(typ)) == op
}

// asciiUpper upper-cases ASCII letters only, as std::toupper in the "C"
// locale does: a Unicode case mapping would match names the reader does not.
func asciiUpper(s string) string {
	b := []byte(s)
	for i, c := range b {
		if 'a' <= c && c <= 'z' {
			b[i] = c - 'a' + 'A'
		}
	}
	return string(b)
}
