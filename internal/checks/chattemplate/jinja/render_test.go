package jinja

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

// decodeVars reads render variables from JSON, keeping object key order as
// Python's dicts do.
func decodeVars(t *testing.T, src string) map[string]any {
	t.Helper()
	dec := json.NewDecoder(strings.NewReader(src))
	dec.UseNumber()
	var read func() any
	read = func() any {
		tok, err := dec.Token()
		if err != nil {
			t.Fatalf("vars %s: %v", src, err)
		}
		switch tok := tok.(type) {
		case json.Delim:
			if tok == '[' {
				out := []any{}
				for dec.More() {
					out = append(out, read())
				}
				_, _ = dec.Token()
				return out
			}
			var m Map
			for dec.More() {
				k, _ := dec.Token()
				m.Keys = append(m.Keys, k.(string))
				m.Vals = append(m.Vals, read())
			}
			_, _ = dec.Token()
			return m
		case json.Number:
			if n, err := tok.Int64(); err == nil {
				return int(n)
			}
			f, _ := tok.Float64()
			return f
		}
		return tok
	}
	m := read().(Map)
	out := map[string]any{}
	for i, k := range m.Keys {
		out[k] = m.Vals[i]
	}
	return out
}

func flatten(ps []Piece) string {
	var b strings.Builder
	for _, p := range ps {
		b.WriteString(p.Text)
	}
	return b.String()
}

const (
	noVars   = `{}`
	convVars = `{"messages": [{"role": "system", "content": "S"}, {"role": "user", "content": " U1 "}, {"role": "assistant", "content": "A"}, {"role": "user", "content": "U2"}], "add_generation_prompt": true, "bos_token": "<s>"}`
	toolVars = `{"tools": [{"type": "function", "function": {"name": "f", "description": "d \"q\" é", "parameters": {"type": "object", "properties": {"x": {"type": "integer"}}, "required": ["x"]}}}], "args": {"b": 1, "a": [true, null, 1.5]}}`
)

// TestRenderMatchesJinja: every want here is what Jinja2 3.1 renders for the
// same template and variables under transformers' settings (an immutable
// sandbox, trim_blocks, lstrip_blocks, loop controls, transformers' tojson,
// raise_exception, and strftime_now frozen to the placeholder). An error
// names the Jinja exception; the evaluator must stop with the matching kind.
func TestRenderMatchesJinja(t *testing.T) {
	cases := []struct {
		tpl, vars, want, err string
	}{
		{"{{ bos_token }}{% for m in messages %}<{{ m.role }}>{{ m['content'] | trim }}\n{% endfor %}{% if add_generation_prompt %}<assistant>{% endif %}", convVars, "<s><system>S\n<user>U1\n<assistant>A\n<user>U2\n<assistant>", ""},
		{"{% for m in messages %}{{ loop.index }}/{{ loop.length }}{{ loop.first }}{{ loop.last }}{{ loop.revindex0 }} {% endfor %}", convVars, "1/4TrueFalse3 2/4FalseFalse2 3/4FalseFalse1 4/4FalseTrue0 ", ""},
		{"{% set c = 0 %}{% for i in [1,2,3] %}{% set c = c + 1 %}{{ c }}{% endfor %}|{{ c }}", noVars, "111|0", ""},
		{"{% set ns = namespace(n=0) %}{% for i in range(4) %}{% set ns.n = ns.n + i %}{% endfor %}{{ ns.n }}", noVars, "6", ""},
		{"{% for m in messages if m.role != 'system' %}{{ m.role }}{% if not loop.last %},{% endif %}{% endfor %}", convVars, "user,assistant,user", ""},
		{"{% for m in messages %}{% if m.role == 'assistant' %}{% break %}{% endif %}{{ m.role }} {% endfor %}", convVars, "system user ", ""},
		{"{% for m in messages %}{% if loop.index0 is even %}{% continue %}{% endif %}{{ m.role }} {% endfor %}", convVars, "user user ", ""},
		{"{% for x in [] %}a{% else %}empty{% endfor %}", noVars, "empty", ""},
		{"{% macro m(a, b='q') %}[{{ a }}{{ b }}]{% endmacro %}{{ m(1) }}{{ m(1, b=2) }}{{ m('x', 'y') }}", noVars, "[1q][12][xy]", ""},
		{"{% set x = 1 %}{% macro m() %}{{ x }}{% endmacro %}{% set x = 2 %}{{ m() }}", noVars, "2", ""},
		{"{{ tools | tojson }}", toolVars, "[{\"type\": \"function\", \"function\": {\"name\": \"f\", \"description\": \"d \\\"q\\\" \u00e9\", \"parameters\": {\"type\": \"object\", \"properties\": {\"x\": {\"type\": \"integer\"}}, \"required\": [\"x\"]}}}]", ""},
		{"{{ tools[0] | tojson(indent=2) }}", toolVars, "{\n  \"type\": \"function\",\n  \"function\": {\n    \"name\": \"f\",\n    \"description\": \"d \\\"q\\\" \u00e9\",\n    \"parameters\": {\n      \"type\": \"object\",\n      \"properties\": {\n        \"x\": {\n          \"type\": \"integer\"\n        }\n      },\n      \"required\": [\n        \"x\"\n      ]\n    }\n  }\n}", ""},
		{"{{ args | tojson }}|{{ args | tojson(sort_keys=true) }}|{{ args|tojson(separators=(',', ':')) }}", toolVars, "{\"b\": 1, \"a\": [true, null, 1.5]}|{\"a\": [true, null, 1.5], \"b\": 1}|{\"b\":1,\"a\":[true,null,1.5]}", ""},
		{"{{ args }}|{{ args.a }}|{{ (1, 'x') }}|{{ ['it\\'s', \"q\\\"\"] }}", toolVars, "{'b': 1, 'a': [True, None, 1.5]}|[True, None, 1.5]|(1, 'x')|[\"it's\", 'q\"']", ""},
		{"{{ 1.0 }} {{ 1e20 }} {{ 0.1 }} {{ 1/3 }} {{ 10/2 }} {{ 7 // 2 }} {{ -7 // 2 }} {{ 7 % 3 }} {{ 2 ** 10 }} {{ true }} {{ none }}", noVars, "1.0 1e+20 0.1 0.3333333333333333 5.0 3 -4 1 1024 True None", ""},
		{"{{ 'a,b,,c'.split(',') }} {{ ' a  b '.split() }} {{ 'a b c'.split(' ', 1) }} {{ 'a,b,c'.rsplit(',', 1) }}", noVars, "['a', 'b', '', 'c'] ['a', 'b'] ['a', 'b c'] ['a,b', 'c']", ""},
		{"{{ '  x  '.strip() }}|{{ 'xxhixx'.strip('x') }}|{{ '  x'.lstrip() }}|{{ 'x  '.rstrip() }}|{{ 'a\\nb\\r\\nc'.splitlines() }}", noVars, "x|hi|x|x|['a', 'b', 'c']", ""},
		{"{{ 'Hello'.startswith('He') }} {{ 'Hello'.endswith(('x', 'lo')) }} {{ 'hello world'.title() }} {{ 'hELLO'.capitalize() }} {{ 'abc'.upper() }}", noVars, "True True Hello World Hello ABC", ""},
		{"{{ 'a-b-c'.replace('-', '+') }} {{ 'aaa'.replace('a', 'b', 2) }} {{ 'abcabc'.find('c') }} {{ 'abcabc'.rfind('c') }} {{ 'abcabc'.count('b') }}", noVars, "a+b+c bba 2 5 2", ""},
		{"{{ ', '.join(['a', 'b']) }} {{ '{} and {}'.format(1, 'x') }} {{ '{0}{0}{name}'.format('a', name='n') }} {{ '%s-%d' % ('a', 3) }} {{ '%s'|format('z') }}", noVars, "a, b 1 and x aan a-3 z", ""},
		{"{{ 'abcdef'[1:3] }} {{ 'abcdef'[::-1] }} {{ 'abcdef'[-2:] }} {{ [1,2,3,4][::2] }} {{ 'abc'[0] }} {{ [1,2,3][-1] }}", noVars, "bc fedcba ef [1, 3] a 3", ""},
		{"{{ messages | selectattr('role', 'equalto', 'user') | map(attribute='content') | join('|') }}", convVars, " U1 |U2", ""},
		{"{{ messages | rejectattr('role', 'in', ['user', 'system']) | list | length }} {{ messages | map(attribute='role') | unique | list }}", convVars, "1 ['system', 'user', 'assistant']", ""},
		{"{{ [3, 1, 2] | sort }} {{ ['b', 'A', 'a'] | sort }} {{ [3,1,2]|sort(reverse=true) }} {{ [1,2,3]|sum }} {{ [4,2,9]|max }} {{ [4,2,9]|min }}", noVars, "[1, 2, 3] ['A', 'a', 'b'] [3, 2, 1] 6 9 2", ""},
		{"{{ {'b': 1, 'a': 2} | dictsort }} {{ {'b': 1, 'a': 2} | items | list }} {% for k, v in {'x': 1, 'y': 2}.items() %}{{ k }}={{ v }};{% endfor %}", noVars, "[('a', 2), ('b', 1)] [('b', 1), ('a', 2)] x=1;y=2;", ""},
		{"{{ x | default('d') }} {{ '' | default('d', true) }} {{ none | default('d') }} {{ x is defined }} {{ none is none }} {{ 'a' is string }} {{ {} is mapping }}", noVars, "d d None False True True True", ""},
		{"{{ 'a\\nb\\n\\nc' | indent(2) }}|{{ 'a\\nb' | indent(2, true) }}|{{ 'a\\n\\nb' | indent(2, blank=true) }}", noVars, "a\n  b\n\n  c|  a\n  b|a\n  \n  b", ""},
		{"{{ '<a href=\"x\">&\\'' | e }} {{ 'x' | safe }} {{ 'hello world foo' | wordcount }} {{ 'Hello World' | lower }} {{ 'hello-world (x)' | title }}", noVars, "&lt;a href=&#34;x&#34;&gt;&amp;&#39; x 3 hello world Hello-World (X)", ""},
		{"{{ '42' | int }} {{ '4.7' | int }} {{ 'x' | int }} {{ 3.9 | int }} {{ '2.5' | float }} {{ 2.5 | round }} {{ 3.14159 | round(2) }} {{ -3 | abs }}", noVars, "42 4 0 3 2.5 2.0 3.14 3", ""},
		{"{{ [1, 2, 3] | first }} {{ [1, 2, 3] | last }} {{ 'abc' | list }} {{ 'abc' | reverse }} {{ [1,2] | reverse | list }} {{ 'abc' | length }}", noVars, "1 3 ['a', 'b', 'c'] cba [2, 1] 3", ""},
		{"{{ 'x' in 'xyz' }} {{ 'q' not in ['a'] }} {{ 'k' in {'k': 1} }} {{ 1 == 1.0 }} {{ [1] == [1] }} {{ 'a' < 'b' }} {{ (1 and 'x') }} {{ (0 or 'y') }}", noVars, "True True True True True True x y", ""},
		{"{{ 'a' ~ 1 ~ none }} {{ 'ab' * 3 }} {{ [1] + [2] }} {{ 'x' if true else 'y' }}{{ 'z' if false }}|", noVars, "a1None ababab [1, 2] x|", ""},
		{"{% set a, b = 1, 2 %}{{ a }}{{ b }} {% set t %}captured {{ a }}{% endset %}{{ t }} {% filter upper %}up{% endfilter %} {% set u | trim %}  pad  {% endset %}[{{ u }}]", noVars, "12 captured 1 UP [pad]", ""},
		{"{{ d.get('k') }} {{ d.get('z', 'def') }} {{ d.keys() | list }} {{ d.values() | list }} {{ d.k }} {{ d['k'] }}", "{\"d\": {\"k\": \"v\", \"j\": \"w\"}}", "v def ['k', 'j'] ['v', 'w'] v v", ""},
		{"{% if messages[0]['role'] == 'system' %}{% set sys = messages[0]['content'] %}{% set rest = messages[1:] %}{% else %}{% set rest = messages %}{% endif %}{{ sys }}|{% for m in rest %}{{ m.content }}{% endfor %}", convVars, "S| U1 AU2", ""},
		{"{{ strftime_now('%Y-%m-%d') }}", noVars, "[current date]", ""},
		{"{{ raise_exception('no system role') }}", noVars, "", "TemplateError"},
		{"{{ x.y }}", noVars, "", "UndefinedError"},
		{"{{ messages[0].nope }}|{{ messages[0].nope is defined }}", convVars, "|False", ""},
		{"{{ 'a' + 1 }}", noVars, "", "TypeError"},
		{"{% for m in messages %}{{ m.content.lstrip() }}{{ loop.cycle('-', '+') }}{% endfor %}", convVars, "S-U1 +A-U2+", ""},
		{"{{ messages[::-1] | map(attribute='role') | join(',') }} {{ (messages | length) - 1 }}", convVars, "user,assistant,user,system 3", ""},
		{"{{ 'AbC'.isupper() }} {{ 'abc'.islower() }} {{ '123'.isdigit() }} {{ ' '.isspace() }} {{ 'a b'.split(' ') | length }}", noVars, "False True True True 2", ""},
		{"{{ x is none }} {{ 1 is number }} {{ 1.5 is float }} {{ 1 is integer }} {{ true is boolean }} {{ [] is iterable }} {{ 'a' is sequence }} {{ 3 is odd }} {{ 4 is divisibleby 2 }}", noVars, "False True True True True True True True True", ""},
		{"{{ [1, 'a'] | tojson }} {{ '\u00e9\\n\"' | tojson }} {{ '\u00e9' | tojson(ensure_ascii=true) }} {{ {} | tojson }} {{ [] | tojson(indent=2) }} {{ 1.0 | tojson }}", noVars, "[1, \"a\"] \"\u00e9\\n\\\"\" \"\\u00e9\" {} [] 1.0", ""},
		{"{{ range(3) | list }} {{ range(1, 7, 2) | list }} {{ range(5, 0, -2) | list }}", noVars, "[0, 1, 2] [1, 3, 5] [5, 3, 1]", ""},
		{"{{ messages | selectattr('content') | list | length }} {{ ['', 'a', none] | select | list }} {{ [1,2,3,4] | select('odd') | list }} {{ [1,2,3] | reject('equalto', 2) | list }}", convVars, "4 ['a'] [1, 3] [1, 3]", ""},
		{"{{ ['a', 'b'] | map('upper') | join }} {{ ['x', 'y'] | join(attribute='0') if false else 'n' }}", noVars, "AB n", ""},
		{"{% set ns = namespace(found=false) %}{% for m in messages %}{% if m.role == 'user' %}{% set ns.found = true %}{% endif %}{% endfor %}{{ ns.found }}", convVars, "True", ""},
		{"{{ '  ' ~ (messages[1].content | trim) ~ '\\n' }}", convVars, "  U1\n", ""},
	}
	for _, c := range cases {
		nodes, err := Parse(c.tpl)
		if err != nil {
			t.Fatalf("%q: %v", c.tpl, err)
		}
		got, err := Render(nodes, decodeVars(t, c.vars), DefaultLimits)
		if c.err != "" {
			var raised *RaiseError
			var failed *FailError
			switch {
			case c.err == "TemplateError" && errors.As(err, &raised):
			case c.err != "TemplateError" && errors.As(err, &failed):
			default:
				t.Errorf("%q: err %v, want a %s", c.tpl, err, c.err)
			}
			continue
		}
		if err != nil {
			t.Errorf("%q: %v", c.tpl, err)
			continue
		}
		if s := flatten(got); s != c.want {
			t.Errorf("%q:\n got %q\nwant %q", c.tpl, s, c.want)
		}
	}
}
