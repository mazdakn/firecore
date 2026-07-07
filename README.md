firecore
========

firecore is a reusable Go packet-filtering and packet-matching library. It models firewall-style evaluation with ordered tables, named chains, composable rules, packet metadata, protocol and port/IP set helpers, connection tracking for new vs. established flows, and counters for matched rules.

At the top level, the `engine` package runs packets through one or more tables and records verdicts plus rule traces inside `eval.Context` values. The surrounding domain packages provide the building blocks for that evaluation:

- engine
- table
- rule
- eval
- packet
- set
- proto
- port
- conntrack
- counter
