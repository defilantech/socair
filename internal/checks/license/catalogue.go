package license

import (
	"fmt"
	"sort"
	"strings"
)

// Entry is one license the catalogue identifies.
//
// IDs are ScanCode LicenseDB keys (https://scancode-licensedb.aboutcode.org/,
// whose data is CC-BY-4.0; only keys are used here), because SPDX lists few
// model licenses. A license ScanCode has no key for, or keys only by dated
// revision when a model card names no revision, has a "socair-" key.
type Entry struct {
	ID   string
	Name string
	// SPDX is the SPDX identifier, for the licenses SPDX lists.
	SPDX string
	// Family groups the revisions of one publisher's license. A model card
	// naming a later revision than its declared base model's is not a
	// disagreement; naming another family is.
	Family string
	// Tags are the model-card license and license_name values, and GGUF
	// general.license values, that name it. Lowercase.
	Tags []string
	// Links are license_link URL prefixes that name it: lowercase, without
	// the scheme or "www.".
	Links []string
	// Texts identify a LICENSE file by phrases: any one rule whose phrases all
	// appear names this license.
	Texts []textRule
	// Body names an embedded fingerprint (bodies/<Body>.txt) that identifies
	// a file holding the whole license text and nothing material beside it.
	Body string
	// BaseRepos are Hugging Face repo-id prefixes, lowercase, whose publisher
	// releases every model under this license. A declared base model that
	// matches one is listed as that license's source, never as the
	// artifact's own statement.
	BaseRepos []string
	// Obligations are usage-policy terms of the license that a scan cannot
	// check. They are listed, never marked met.
	Obligations []string
}

// textRule is a set of phrases that together identify a license text.
// MaxWords, when set, bounds the text: a short notice that a longer text
// could also contain identifies only a short file.
type textRule struct {
	Phrases  []string
	MaxWords int
}

func phrases(p ...string) textRule { return textRule{Phrases: p} }

const (
	llamaAUP     = "the Acceptable Use Policy for the Llama Materials, incorporated into the license"
	llamaMAU     = "a licensee whose products had more than 700 million monthly active users on the release date must request a license from Meta"
	llamaEU      = "the Acceptable Use Policy does not grant the rights to its multimodal models to an individual domiciled in, or a company with a principal place of business in, the European Union (end users of a product that incorporates them are not restricted)"
	builtLlama   = "a product or service that distributes it must provide a copy of the agreement and display \"Built with Llama\", and a model trained from it must have a name that begins with \"Llama\""
	qwenMAU      = "commercial use by a product or service with more than 100 million monthly active users requires a license from Alibaba Cloud"
	railFlowDown = "use-based restrictions (Attachment A) that must be carried, as enforceable provisions, into any agreement under which you distribute it or a derivative"
)

// catalogue is every license the scanner identifies. TestCatalogue holds it
// to its own rules: unique ids and tags, and no text that two entries claim.
var catalogue = []Entry{
	// Permissive and Creative Commons licenses.
	{
		ID: "apache-2.0", Name: "Apache License 2.0", SPDX: "Apache-2.0",
		Tags:  []string{"apache-2.0", "apache 2.0", "apache2.0", "apache license 2.0", "apache license, version 2.0"},
		Links: []string{"apache.org/licenses/license-2.0", "opensource.org/licenses/apache-2.0"},
		Body:  "apache-2.0",
		// The standard notice that applies the license to a file.
		Texts: []textRule{{Phrases: []string{"licensed under the apache license version 2 0",
			"you may not use this file except in compliance with the license"}, MaxWords: 150}},
	},
	{
		ID: "mit", Name: "MIT License", SPDX: "MIT",
		Tags:  []string{"mit", "mit license"},
		Links: []string{"opensource.org/licenses/mit"},
		Body:  "mit",
	},
	{
		ID: "bsd-new", Name: "BSD 3-Clause License", SPDX: "BSD-3-Clause",
		Tags:  []string{"bsd-3-clause"},
		Links: []string{"opensource.org/licenses/bsd-3-clause"},
		Body:  "bsd-new",
	},
	{
		ID: "bsd-simplified", Name: "BSD 2-Clause License", SPDX: "BSD-2-Clause",
		Tags:  []string{"bsd-2-clause"},
		Links: []string{"opensource.org/licenses/bsd-2-clause"},
		Body:  "bsd-simplified",
	},
	{
		ID: "cc-by-4.0", Name: "Creative Commons Attribution 4.0 International", SPDX: "CC-BY-4.0",
		Tags:  []string{"cc-by-4.0"},
		Links: []string{"creativecommons.org/licenses/by/4.0"},
		Texts: []textRule{phrases("creative commons attribution 4.0 international public license"),
			phrases("creative commons attribution 4.0 international license")},
	},
	{
		ID: "cc-by-sa-4.0", Name: "Creative Commons Attribution-ShareAlike 4.0 International", SPDX: "CC-BY-SA-4.0",
		Tags:  []string{"cc-by-sa-4.0"},
		Links: []string{"creativecommons.org/licenses/by-sa/4.0"},
		Texts: []textRule{phrases("creative commons attribution-sharealike 4.0 international public license"),
			phrases("creative commons attribution-sharealike 4.0 international license")},
	},
	{
		ID: "cc-by-nc-4.0", Name: "Creative Commons Attribution-NonCommercial 4.0 International", SPDX: "CC-BY-NC-4.0",
		Tags:  []string{"cc-by-nc-4.0"},
		Links: []string{"creativecommons.org/licenses/by-nc/4.0"},
		Texts: []textRule{phrases("creative commons attribution-noncommercial 4.0 international public license"),
			phrases("creative commons attribution-noncommercial 4.0 international license")},
		Obligations: []string{"non-commercial use only"},
	},
	{
		ID: "cc-by-nc-sa-4.0", Name: "Creative Commons Attribution-NonCommercial-ShareAlike 4.0 International", SPDX: "CC-BY-NC-SA-4.0",
		Tags:  []string{"cc-by-nc-sa-4.0"},
		Links: []string{"creativecommons.org/licenses/by-nc-sa/4.0"},
		Texts: []textRule{phrases("creative commons attribution-noncommercial-sharealike 4.0 international public license"),
			phrases("creative commons attribution-noncommercial-sharealike 4.0 international license")},
		Obligations: []string{"non-commercial use only"},
	},
	{
		ID: "openmdw-1.0", Name: "OpenMDW License Agreement 1.0", SPDX: "OpenMDW-1.0",
		Tags:  []string{"openmdw-1.0", "openmdw"},
		Texts: []textRule{phrases("openmdw license agreement, version 1.0")},
	},

	// Meta Llama.
	{
		ID: "llama-2-license-2023", Name: "Llama 2 Community License Agreement", Family: "llama",
		Tags:      []string{"llama2"},
		Links:     []string{"ai.meta.com/llama/license"},
		BaseRepos: []string{"meta-llama/llama-2-"},
		Texts:     []textRule{phrases("llama 2 community license agreement", "llama 2 version release date")},
		Obligations: []string{llamaAUP, llamaMAU,
			"the Llama Materials and their outputs may not be used to improve any other large language model"},
	},
	{
		ID: "socair-llama-3-license-2024", Name: "Meta Llama 3 Community License Agreement", Family: "llama",
		Tags:      []string{"llama3"},
		Links:     []string{"llama.meta.com/llama3/license"},
		BaseRepos: []string{"meta-llama/meta-llama-3-"},
		Texts:     []textRule{phrases("meta llama 3 community license agreement", "meta llama 3 version release date")},
		Obligations: []string{llamaAUP, llamaMAU,
			"a product or service that distributes it must provide a copy of the agreement and display \"Built with Meta Llama 3\", and a model trained from it must have a name that begins with \"Llama 3\"",
			"the Llama Materials and their outputs may not be used to improve any other large language model"},
	},
	{
		ID: "llama-3.1-license-2024", Name: "Llama 3.1 Community License Agreement", Family: "llama",
		Tags:        []string{"llama3.1"},
		Links:       []string{"llama.meta.com/llama3_1/license", "llama.com/llama3_1/license"},
		BaseRepos:   []string{"meta-llama/llama-3.1-", "meta-llama/meta-llama-3.1-"},
		Texts:       []textRule{phrases("llama 3.1 community license agreement", "llama 3.1 version release date")},
		Obligations: []string{llamaAUP, llamaMAU, builtLlama},
	},
	{
		ID: "llama-3.2-license-2024", Name: "Llama 3.2 Community License Agreement", Family: "llama",
		Tags:        []string{"llama3.2"},
		Links:       []string{"llama.com/llama3_2/license"},
		BaseRepos:   []string{"meta-llama/llama-3.2-"},
		Texts:       []textRule{phrases("llama 3.2 community license agreement", "llama 3.2 version release date")},
		Obligations: []string{llamaAUP, llamaMAU, builtLlama, llamaEU},
	},
	{
		ID: "llama-3.3-license-2024", Name: "Llama 3.3 Community License Agreement", Family: "llama",
		Tags:        []string{"llama3.3"},
		Links:       []string{"llama.com/llama3_3/license"},
		BaseRepos:   []string{"meta-llama/llama-3.3-"},
		Texts:       []textRule{phrases("llama 3.3 community license agreement", "llama 3.3 version release date")},
		Obligations: []string{llamaAUP, llamaMAU, builtLlama, llamaEU},
	},
	{
		ID: "llama-4-cla-2025", Name: "Llama 4 Community License Agreement", Family: "llama",
		Tags:        []string{"llama4"},
		Links:       []string{"llama.com/llama4/license"},
		BaseRepos:   []string{"meta-llama/llama-4-"},
		Texts:       []textRule{phrases("llama 4 community license agreement", "llama 4 version effective date")},
		Obligations: []string{llamaAUP, llamaMAU, builtLlama, llamaEU},
	},

	// Google Gemma. ScanCode keys each revision by date; a model card's
	// "gemma" names none, so the terms are one entry.
	{
		ID: "socair-gemma-terms-of-use", Name: "Gemma Terms of Use", Family: "gemma",
		Tags:  []string{"gemma"},
		Links: []string{"ai.google.dev/gemma/terms"},
		BaseRepos: []string{"google/gemma-2b", "google/gemma-7b", "google/gemma-1.1-", "google/gemma-2-", "google/gemma-3-",
			"google/gemma-3n-", "google/codegemma-", "google/recurrentgemma-", "google/paligemma", "google/shieldgemma-"},
		Texts: []textRule{phrases("gemma terms of use", "gemma prohibited use policy")},
		Obligations: []string{"the Gemma Prohibited Use Policy, incorporated into the terms",
			"its use restrictions must be included as an enforceable provision in any agreement under which you distribute it or a derivative",
			"Google may restrict, remotely or otherwise, use it believes violates the terms"},
	},

	// Alibaba Qwen.
	{
		ID: "qwen-2024", Name: "Qwen License Agreement", Family: "qwen",
		Tags:  []string{"qwen"},
		Texts: []textRule{phrases("qwen license agreement", "qwen license agreement release date")},
		Obligations: []string{qwenMAU,
			"a model trained or improved from it and distributed must display \"Built with Qwen\" or \"Improved using Qwen\" in its documentation"},
	},
	{
		ID: "tongyi-qianwen-2023", Name: "Tongyi Qianwen License Agreement", Family: "qwen",
		Tags:        []string{"tongyi-qianwen"},
		Texts:       []textRule{phrases("tongyi qianwen license agreement", "tongyi qianwen release date")},
		Obligations: []string{qwenMAU},
	},
	{
		ID: "socair-qwen-research-2024", Name: "Qwen Research License Agreement", Family: "qwen",
		Tags:  []string{"qwen-research"},
		Texts: []textRule{phrases("qwen research license agreement")},
		Obligations: []string{"non-commercial use only: research or evaluation",
			"a model trained or improved from it and distributed must display \"Built with Qwen\" or \"Improved using Qwen\" in its documentation"},
	},

	// DeepSeek, NVIDIA, Mistral, TII Falcon.
	{
		ID: "deepseek-la-1.0", Name: "DeepSeek License Agreement 1.0",
		Tags:        []string{"deepseek", "deepseek-license"},
		Texts:       []textRule{phrases("deepseek license agreement", "version 1.0, 23 october 2023")},
		Obligations: []string{railFlowDown},
	},
	{
		// ScanCode keys the agreement's revisions by date; a model card's
		// license_name names none.
		ID: "socair-nvidia-open-model", Name: "NVIDIA Open Model License Agreement",
		Tags:  []string{"nvidia-open-model-license"},
		Links: []string{"nvidia.com/en-us/agreements/enterprise-software/nvidia-open-model-license"},
		Texts: []textRule{phrases("nvidia open model license agreement")},
		Obligations: []string{"use must be consistent with NVIDIA's Trustworthy AI terms",
			"bypassing, disabling, or reducing the efficacy of a safety guardrail in the model ends the license",
			"a distribution must include the agreement and the notice \"Licensed by NVIDIA Corporation under the NVIDIA Open Model License\""},
	},
	{
		ID: "socair-mistral-research-0.1", Name: "Mistral AI Research License", Family: "mistral",
		Tags:        []string{"mrl"},
		Links:       []string{"mistral.ai/licenses/mrl-0.1", "mistral.ai/licences/mrl-0.1"},
		Texts:       []textRule{phrases("mistral ai research license")},
		Obligations: []string{"research use only: the models, derivatives, and outputs may be used only for research purposes"},
	},
	{
		ID: "socair-mistral-non-production-0.1", Name: "Mistral AI Non-Production License", Family: "mistral",
		Tags:        []string{"mnpl"},
		Links:       []string{"mistral.ai/licenses/mnpl-0.1", "mistral.ai/licences/mnpl-0.1"},
		Texts:       []textRule{phrases("mistral ai non-production license")},
		Obligations: []string{"non-production use only: testing, research, personal, or evaluation purposes in non-production environments"},
	},
	{
		ID: "falcon-2-11b-1.0", Name: "Falcon 2 11B TII License 1.0", Family: "falcon",
		Texts:       []textRule{phrases("falcon 2 11b tii license version 1.0")},
		Obligations: []string{"the Falcon Acceptable Use Policy, which its use-based restrictions must carry into any agreement under which you distribute it"},
	},
	{
		ID: "socair-tii-falcon-license", Name: "TII Falcon License", Family: "falcon",
		Tags:  []string{"falcon-llm-license"},
		Texts: []textRule{phrases("tii falcon license", "acceptable use policy")},
		Obligations: []string{"the Falcon Acceptable Use Policy (hosted at FalconLLM.tii.ae and updated from time to time), which its use-based restrictions must carry into any agreement under which you distribute it",
			"a publication of a derivative must state that it \"is built using artificial intelligence technology from the Technology Innovation Institute\""},
	},

	// Responsible AI licenses.
	{
		ID: "bigscience-rail-1.0", Name: "BigScience RAIL License v1.0", Family: "rail",
		Tags:        []string{"bigscience-bloom-rail-1.0"},
		Texts:       []textRule{phrases("bigscience rail license v1.0")},
		Obligations: []string{railFlowDown},
	},
	{
		ID: "bigscience-open-rail-m", Name: "BigScience Open RAIL-M License", Family: "rail",
		Tags:        []string{"bigscience-openrail-m"},
		Texts:       []textRule{phrases("bigscience open rail-m license")},
		Obligations: []string{railFlowDown},
	},
	{
		ID: "bigcode-open-rail-m-v1", Name: "BigCode Open RAIL-M v1 License Agreement", Family: "rail",
		Tags:        []string{"bigcode-openrail-m"},
		Texts:       []textRule{phrases("bigcode open rail-m v1 license agreement")},
		Obligations: []string{"compliance with the use restrictions in Attachment A is a condition of the license, and they must be passed on when the model is shared"},
	},
	{
		ID: "socair-creativeml-openrail-m", Name: "CreativeML Open RAIL-M", Family: "rail",
		Tags:        []string{"creativeml-openrail-m"},
		Texts:       []textRule{phrases("creativeml open rail-m", "dated august 22, 2022")},
		Obligations: []string{railFlowDown},
	},
	{
		ID: "bigscience-open-rail-m2", Name: "CreativeML Open RAIL++-M License", Family: "rail",
		Tags:        []string{"openrail++"},
		Texts:       []textRule{phrases("creativeml open rail++-m license")},
		Obligations: []string{railFlowDown},
	},
	{
		ID: "socair-openrail", Name: "Open RAIL license (variant not stated)", Family: "rail",
		Tags:        []string{"openrail"},
		Obligations: []string{"Open RAIL licenses carry use-based restrictions; which ones depends on the variant, which the model card does not name"},
	},

	// MIT with a publisher's modification: identified as itself, never as MIT.
	{
		ID: "moonshot-ai-modified-mit-2025", Name: "Moonshot AI Modified MIT License",
		Texts: []textRule{phrases("permission is hereby granted, free of charge", "our only modification part is that",
			"more than 100 million monthly active users", "prominently display \"kimi")},
		Obligations: []string{"a commercial product or service with more than 100 million monthly active users, or more than 20 million US dollars in monthly revenue, must display the model's name (\"Kimi K2\") on its user interface"},
	},
	{
		ID: "minimax-mit-variant-2025", Name: "MiniMax MIT Variant",
		Texts: []textRule{phrases("permission is hereby granted, free of charge", "our only modification is that",
			"used for any of your commercial products or services, you shall prominently display \"minimax")},
		Obligations: []string{"a commercial product or service must display the model's name (\"MiniMax ...\") on its user interface"},
	},

	// Licenses ScanCode does not key.
	{
		ID: "socair-tencent-hunyuan-community", Name: "Tencent Hunyuan Community License Agreement",
		Tags:  []string{"tencent-hunyuan-community"},
		Texts: []textRule{phrases("tencent hunyuan community license agreement")},
		Obligations: []string{"the license does not apply in the European Union, the United Kingdom, or South Korea",
			"the Acceptable Use Policy in its Exhibit A",
			"a licensee whose products had more than 100 million monthly active users on the release date must request a license from Tencent",
			"products or services developed with it must be marked \"Powered by Tencent Hunyuan\""},
	},
	{
		ID: "socair-glm-4", Name: "GLM-4 License",
		Tags:  []string{"glm-4"},
		Texts: []textRule{phrases("the glm-4-9b license")},
		Obligations: []string{"commercial use requires registration with Zhipu AI",
			"a product or service that distributes it must display \"Built with glm-4\", and a model trained from it must have a name that begins with \"glm-4\""},
	},
}

// Placeholder values a model card or GGUF uses to say the license is stated
// elsewhere, or not at all. They are read, never matched.
var placeholders = map[string]string{
	"other":   "names a license outside Hugging Face's list; the license_name, license_link, or LICENSE file says which",
	"unknown": "says the license is unknown",
}

var (
	byID   = map[string]*Entry{}
	byTag  = map[string]*Entry{}
	bodies = map[string]body{}
)

func init() {
	for i := range catalogue {
		e := &catalogue[i]
		byID[e.ID] = e
		if e.Family == "" {
			e.Family = e.ID
		}
		for _, t := range e.Tags {
			byTag[t] = e
		}
		for j, r := range e.Texts {
			for k, p := range r.Phrases {
				e.Texts[j].Phrases[k] = phrase(p)
			}
		}
		if e.Body != "" {
			b, err := loadBody(e.Body)
			if err != nil {
				panic(fmt.Sprintf("license catalogue %s: %v", e.ID, err))
			}
			bodies[e.ID] = b
		}
	}
}

// Lookup returns the catalogue entry a name refers to: its id, its SPDX id,
// or one of its tags, ignoring case.
func Lookup(name string) (Entry, bool) {
	n := strings.ToLower(strings.TrimSpace(name))
	if e, ok := byID[n]; ok {
		return *e, true
	}
	if e, ok := byTag[n]; ok {
		return *e, true
	}
	for _, e := range catalogue {
		if e.SPDX != "" && strings.ToLower(e.SPDX) == n {
			return e, true
		}
	}
	return Entry{}, false
}

// Catalogue returns every entry, sorted by id.
func Catalogue() []Entry {
	out := append([]Entry(nil), catalogue...)
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// byLink returns the entry whose license_link prefix a URL starts with.
func byLink(link string) (*Entry, bool) {
	u := strings.ToLower(strings.TrimSpace(link))
	u = strings.TrimPrefix(strings.TrimPrefix(u, "https://"), "http://")
	u = strings.TrimPrefix(u, "www.")
	for i := range catalogue {
		for _, l := range catalogue[i].Links {
			if strings.HasPrefix(u, l) {
				return &catalogue[i], true
			}
		}
	}
	return nil, false
}

// byBaseRepo returns the entry whose publisher releases the repo under it.
func byBaseRepo(repo string) (*Entry, bool) {
	r := strings.ToLower(strings.TrimSpace(repo))
	for i := range catalogue {
		for _, p := range catalogue[i].BaseRepos {
			if strings.HasPrefix(r, p) {
				return &catalogue[i], true
			}
		}
	}
	return nil, false
}
