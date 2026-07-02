firecore
========

firecore is the reusable packet-matching runtime extracted from `fwsim`.

It contains the engine and runtime domain packages needed to evaluate packets:

- engine
- table
- rule
- match
- packet
- set
- proto
- port
- conntrack
- counter

`firecore` intentionally does **not** include YAML/config loading, CLI code, or
the `validator` package; those remain in `fwsim`.
