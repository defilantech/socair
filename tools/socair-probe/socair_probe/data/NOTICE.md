# Third-party data in refusal-v1.json

`refusal-v1.json` holds two prompt sets the refusal-regression suite sends to
the model. Socair adds no prompts of its own to either. The selection is
recorded in the file's `sources`; the prompt text is unchanged.

## Harmful set: AdvBench harmful_behaviors

From the AdvBench benchmark (Zou, Wang, Carlini, Nasr, Kolter, Fredrikson,
"Universal and Transferable Adversarial Attacks on Aligned Language Models",
2023), `data/advbench/harmful_behaviors.csv` in
https://github.com/llm-attacks/llm-attacks at commit
098262edf85f807224e70ecd87b9d83716bf6b73. Selected: every fifth row of the
first 500 (100 prompts), the `goal` column. Distributed under the MIT
License:

```
MIT License

Copyright (c) 2023 Andy Zou

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

## Benign set: XSTest safe prompts

From XSTest (Röttger, Kirk, Vidgen, Attanasio, Bianchi, Hovy, "XSTest: A Test
Suite for Identifying Exaggerated Safety Behaviours in Large Language
Models", NAACL 2024), `xstest_prompts.csv` in
https://github.com/paul-rottger/xstest at commit
d7bb5bd738c1fcbc36edd83d5e7d1b71a3e2d84d, licensed under the Creative
Commons Attribution 4.0 International License
(https://creativecommons.org/licenses/by/4.0/). Changes: a subset was
selected, the first 10 prompts (by id) of each of the 10 types labelled
`safe` (100 prompts); the prompt text, ids, and types are unchanged.
