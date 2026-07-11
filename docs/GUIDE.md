# firecore user guide

firecore lets you build firewall-style packet-filtering policies in Go and evaluate packets against them. It borrows its evaluation model from nftables/iptables: an **engine** runs a packet through one or more **tables**, in order; each table walks a graph of named **chains**; each chain is an ordered list of **rules**; each rule either matches or doesn't, and on match applies an **action**.

This guide covers every public package. For a five-minute start, see the [README](../README.md#quick-start).

## Table of contents

- [Core concepts](#core-concepts)
  - [Engine](#engine)
  - [Table](#table)
  - [Chain](#chain)
  - [Rule and Action](#rule-and-action)
- [Building rules](#building-rules)
  - [Match option reference](#match-option-reference)
  - [Negation](#negation)
  - [Named sets vs. single values](#named-sets-vs-single-values)
  - [Match evaluation order](#match-evaluation-order)
- [Control flow: accept, drop, pass, jump, return](#control-flow-accept-drop-pass-jump-return)
- [Connection tracking](#connection-tracking)
- [Packets](#packets)
- [Sets](#sets)
- [Protocols and ports](#protocols-and-ports)
- [Payload matching](#payload-matching)
- [Packet counters](#packet-counters)
- [Error handling](#error-handling)
- [Worked example: jump, return, and pass across tables](#worked-example-jump-return-and-pass-across-tables)

## Core concepts

### Engine

`Engine` is the entry point. It holds an ordered list of tables and runs a packet through them.

```go
func New(opts ...Option) *Engine
func WithConntrack() Option

func (e *Engine) AddTable(t *Table)
func (e *Engine) Evaluate(ctx *eval.Context) (*eval.Result, error)
```

- `New` builds an engine. Pass `WithConntrack()` to enable new/established connection-state tracking (see [Connection tracking](#connection-tracking)).
- `AddTable` registers a table and keeps `Engine.Tables` sorted ascending by `Table.Order`.
- `Evaluate` runs `ctx.Packet` through each table in order:
  - If conntrack is enabled, it looks up the connection state and sets `ctx.ConnState` before matching.
  - Tables are tried in ascending `Order` until one produces a terminal verdict (`Accept`/`Drop`) — evaluation stops there.
  - A table that returns `Pass` doesn't decide anything; the packet falls through to the next table.
  - If no table decides, `result.Verdict` is `nil`.
  - If the final verdict is `Accept` and conntrack is enabled, the connection is committed as established (both directions).
- Returns an error if `ctx`/`ctx.Packet` is nil, or if a table's `Match` fails (e.g. a rule jumps to a chain that doesn't exist).

### Table

A `Table` holds a set of named chains and a default (fallthrough) rule.

```go
func NewTable(name string, order uint64, defaultAction rule.Action) (*Table, error)

func (t *Table) AddChain(c *Chain)
func (t *Table) SetEntryChain(name string)
func (t *Table) EntryChain() string
func (t *Table) Validate() error
func (t *Table) Match(ctx *eval.Context, result *eval.Result) (bool, error)
func (t *Table) MatchDefaultRule(result *eval.Result) bool

func SortTables(tables []*Table)
```

- `NewTable(name, order, defaultAction)` creates a table whose default rule has the given action and is auto-named `"table <name> default action"`. `order` determines this table's position relative to other tables registered on the same engine.
- `AddChain` adds a chain to the table. **The first chain added becomes the entry chain** unless you call `SetEntryChain` explicitly. Chains may reference each other via `rule.WithJump("chainName")` regardless of add order — a chain's jump targets don't need to exist yet at the time it's added.
- `Validate` checks that every `Jump` rule across all of the table's chains targets a chain that actually exists, returning an error naming the offending chain and rule if not. Call it once all chains have been added (e.g. right before handing the table to the engine) to catch a dangling jump target at build time instead of only when a packet happens to reach that rule during `Match`/`Evaluate`. It does not detect jump cycles.
- `Match` evaluates the entry chain. If nothing in it produces a terminal verdict or a `Pass`, the table's default rule runs via `MatchDefaultRule`.
- `Table.DefaultRule` is a public field — you can inspect its `PacketCount()` or swap/clear it (setting it to `nil` disables the fallthrough entirely; `Match` then reports no match with no verdict).

### Chain

A `Chain` is an ordered, named list of rules.

```go
func NewChain(name string) *Chain
func (c *Chain) AddRule(r *rule.Rule)
```

- `AddRule` inserts `r` maintaining ascending order by `r.Order` (stable for equal orders, so insertion order is the tiebreaker — this is why the examples below don't bother setting `Order` when they don't need it).
- A table can hold multiple chains (e.g. an `entry` chain and helper chains reached via `jump`); only the entry chain is walked automatically — others are only reached via `rule.WithJump("chainName")`.

### Rule and Action

```go
type Action int
const (
    Accept Action = iota
    Drop
    Pass
    Jump
    Return
)

func (a Action) IsTerminal() bool          // true for Accept or Drop
func (a Action) Validate() error
func ParseAction(s string) (Action, error) // "accept" | "drop" | "pass" | "jump" | "return" (case-insensitive)

func New(opts ...RuleOption) (*Rule, error)
```

A `Rule` bundles match criteria (protocol, addresses, ports, interfaces, connection state, payload) with an `Action`. Build one with `rule.New` and a list of `With*` options — see the next section.

## Building rules

```go
r, err := rule.New(
    rule.WithName("allow-established"),
    rule.WithProto(proto.TCP),
    rule.WithConnState(conntrack.StateEstablished),
    rule.WithAction(rule.Accept),
)
```

`rule.New` applies every option in order and returns the first error encountered (e.g. an invalid CIDR string or an unparsable payload regex) — always check it.

### Match option reference

All options are `rule.RuleOption` values (`func(*Rule) error`), composed with `rule.New(opts...)`.

| Category | Options |
|---|---|
| Identity / metadata | `WithName(string)`, `WithOrder(uint64)` |
| Action | `WithAction(Action)`, `WithJump(chainName string)` (implies `Action = Jump`) |
| Protocol | `WithProto(proto.Proto)`, `WithNotProto(proto.Proto)` |
| Source port | `WithSrcPort(uint16)`, `WithNotSrcPort(uint16)`, `WithSrcPortSet(set.Set)`, `WithNotSrcPortSet(set.Set)` |
| Destination port | `WithDstPort(uint16)`, `WithNotDstPort(uint16)`, `WithDstPortSet(set.Set)`, `WithNotDstPortSet(set.Set)` |
| Source address | `WithSrcNet(cidr string)`, `WithNotSrcNet(cidr string)`, `WithSrcIPSet(set.Set)`, `WithNotSrcIPSet(set.Set)` |
| Destination address | `WithDstNet(cidr string)`, `WithNotDstNet(cidr string)`, `WithDstIPSet(set.Set)`, `WithNotDstIPSet(set.Set)` |
| Combined IP:port | `WithSrcIPPortSet(set.Set)`, `WithNotSrcIPPortSet(set.Set)`, `WithDstIPPortSet(set.Set)`, `WithNotDstIPPortSet(set.Set)` |
| Ingress interface | `WithSrcIface(string)`, `WithNotSrcIface(string)`, `WithSrcIfaceSet(set.Set)`, `WithNotSrcIfaceSet(set.Set)` |
| Egress interface | `WithDstIface(string)`, `WithNotDstIface(string)`, `WithDstIfaceSet(set.Set)`, `WithNotDstIfaceSet(set.Set)` |
| Connection state | `WithConnState(conntrack.State)`, `WithNotConnState(conntrack.State)` |
| Payload | `WithPayload(regexPattern string)` |

Note on naming: "source" always means the packet's `SrcAddr`/`SrcPort`/ingress interface; "destination" means `DstAddr`/`DstPort`/egress interface.

### Negation

Every positive option has a `Not*` counterpart. Positive and negated forms compose independently — a rule can require membership in one CIDR while excluding a sub-range of it:

```go
rule.WithSrcNet("10.0.0.0/8"), rule.WithNotSrcNet("10.10.0.0/16")
// matches 10.x.x.x except 10.10.x.x
```

Calling both `WithSrcIface("eth0")` and `WithSrcIface("eth1")` accumulates — the rule matches either interface. Adding `WithNotSrcIface("eth1")` on top then excludes it again, net effect: only `eth0`.

### Named sets vs. single values

The singular options (`WithSrcPort`, `WithSrcNet`, `WithSrcIface`, ...) are convenience wrappers for the common case of one value. The `*Set` options (`WithSrcPortSet`, `WithSrcIPSet`, `WithSrcIfaceSet`, `WithSrcIPPortSet`, and their `Not`/`Dst` variants) accept any `set.Set` — built once and reused across many rules — for larger or dynamic membership lists. See [Sets](#sets) for how to build one.

### Match evaluation order

`Rule.Match(pkt)` (equivalent to `MatchWithConntrackState(pkt, conntrack.StateNew)`) and `Rule.MatchWithConntrackState(pkt, state)` check conditions in this order, short-circuiting on the first failure:

1. Connection state (`ConnState`/`NotConnState`)
2. Payload regex
3. Protocol (positive, then negated)
4. Source port, destination port (positive, then negated)
5. Source network, destination network (positive, then negated)
6. Named sets on source, then destination (all positive sets must match; no negated set may match)
7. Source interface, destination interface (positive, then negated)

A condition category that was never configured (nil/empty) is skipped — an empty rule matches everything. On a full match, the rule's packet counter increments before returning `true`.

## Control flow: accept, drop, pass, jump, return

- **Accept** / **Drop** are terminal: the engine stops evaluating immediately and this is the final verdict.
- **Pass** stops evaluation of the *current table* without deciding anything, and lets the engine move on to the next table (by `Order`). If no later table decides, the overall result has a nil verdict — `Pass` at the very last table is effectively "no match."
- **Return** stops evaluation of the *current chain* and hands control back to whichever chain jumped into it (or, if already in the table's entry chain, falls through to the table's default rule).
- **Jump** (`rule.WithJump("chainName")`) transfers evaluation into the named chain of the *same table*. If that chain falls through without a terminal verdict or `Pass` (i.e. every rule in it either doesn't match or hits `Return`), evaluation resumes at the next rule after the jump in the calling chain.

Every rule inspected along the way — including ones in jumped-to chains and, when reached, the table's default rule — is appended to `eval.Result.Trace` in evaluation order, so you can always reconstruct exactly why a packet got its verdict.

See the [worked example](#worked-example-jump-return-and-pass-across-tables) below for all four behaviors combined.

## Connection tracking

```go
type State string
const (
    StateNew         State = "new"
    StateEstablished State = "established"
)
func ParseState(raw string) (State, error) // "new" | "established", case-insensitive

func NewTracker() *Tracker
func (t *Tracker) Lookup(pkt *packet.Packet) (State, error)
func (t *Tracker) CommitAccepted(pkt *packet.Packet) error
```

Pass `firecore.WithConntrack()` to `firecore.New` to enable this. On each `Evaluate` call the engine looks up `ctx.Packet`'s state (`StateNew` if unseen) and stores it on `ctx.ConnState`; rules can then match on it with `rule.WithConnState(conntrack.StateEstablished)`. When a packet is finally `Accept`ed, both directions of the flow (src↔dst swapped) are recorded as `StateEstablished`, so a reply packet on the same flow is recognized without re-walking the full rule set.

Without `WithConntrack()`, `ctx.ConnState` stays `nil` and connection-state rules never match.

## Packets

```go
func New(opts ...PacketOption) *Packet

func WithName(string) PacketOption
func WithProto(proto.Proto) PacketOption
func WithSrcAddr(addr string) PacketOption   // parsed with net.ParseIP
func WithDstAddr(addr string) PacketOption
func WithSrcPort(uint16) PacketOption
func WithDstPort(uint16) PacketOption
func WithIngressIface(string) PacketOption
func WithEgressIface(string) PacketOption
func WithPayload([]byte) PacketOption
```

`packet.New` builds a `*Packet` (`SrcAddr`, `DstAddr net.IP`; `Proto proto.Proto`; `SrcPort`, `DstPort uint16`; `Payload []byte`; `Metadata *Metadata` holding `Name`, `IngressIface`, `EgressIface`). Wrap it for evaluation with `eval.New(pkt)`, which returns an `*eval.Context` — the input to `Engine.Evaluate`. `eval.Result` (the output) has `Verdict *rule.Action` and `Trace []*rule.Rule`.

## Sets

A `set.Set` is a named, reusable, typed collection you attach to a rule via the `*Set` options. All set types share:

```go
type Set interface {
    Add(any) error
    Match(any) bool
    Type() Type // "ip" | "port" | "proto" | "ipport" | "iface"
}
```

| Constructor | Attach with | `Add` accepts |
|---|---|---|
| `set.NewIPSet()` | `WithSrcIPSet` / `WithDstIPSet` (or `Not*`) | `*net.IPNet`, or a CIDR string (`"10.0.0.0/8"`) |
| `set.NewPortSet()` | `WithSrcPortSet` / `WithDstPortSet` (or `Not*`) | `uint16`, a `port.Port`, or a string — numeric (`"443"`), well-known name (`"https"`), or range (`"1024-65535"`) |
| `set.NewIfaceSet()` | `WithSrcIfaceSet` / `WithDstIfaceSet` (or `Not*`) | an interface name string (`"eth0"`) |
| `set.NewIPPortSet()` | `WithSrcIPPortSet` / `WithDstIPPortSet` (or `Not*`) | a single string `"ip-or-cidr,port-or-range"`, e.g. `"8.8.8.8,53"` or `"10.0.0.0/8,1024-2048"` |
| `set.NewProtoSet()` | (used internally for `Proto`/`NotProto`) | a `proto.Proto`, or a name/number string |

Build a set once and reuse it across many rules:

```go
adminSources := set.NewIPSet()
adminSources.Add("10.0.0.0/8")

webPorts := set.NewPortSet()
webPorts.Add("http")
webPorts.Add("https")

r, _ := rule.New(
    rule.WithSrcIPSet(adminSources),
    rule.WithDstPortSet(webPorts),
    rule.WithAction(rule.Accept),
)
```

## Protocols and ports

`proto.Proto` is a `uint8` protocol number with named constants `ICMP` (1), `TCP` (6), `UDP` (17). `proto.Parse(s)` accepts `"tcp"`/`"udp"`/`"icmp"` (case-insensitive) or a numeric string, returning `*Proto`.

`port.Port` represents a single port or a range (`Number`...`End`); `port.Parse(s)` accepts a well-known name (`ftp`, `ssh`, `telnet`, `smtp`, `dns`, `http`, `pop3`, `imap`, `ldap`, `https`, `smb`, `mysql`, `rdp`, `postgresql`, `redis`, `mongodb`), a numeric string, or a `"start-end"` range. Call `.Resolve()` to get the numeric port (resolving the well-known name if needed) for use with `rule.WithSrcPort`/`WithDstPort`, which take a plain `uint16`.

Both `Proto` and `Port` implement `UnmarshalYAML`, so policies can be loaded from YAML config using either form (name or number) without extra glue code.

## Payload matching

```go
func rule.WithPayload(pattern string) RuleOption
```

Compiles `pattern` as a Go regexp (`payload.New` under the hood) and requires it to match `pkt.Payload` (a `[]byte`) in addition to every other condition on the rule. Useful for simple deep-packet-inspection rules, e.g. `rule.WithPayload(`(?i)api_key=[A-Za-z0-9_-]+`)`.

## Packet counters

```go
func (r *Rule) PacketCount() uint64
func (r *Rule) IncrementPacketCount()
func (r *Rule) ResetPacketCount()
```

Every `Rule` (including a table's `DefaultRule`) carries an atomic counter, incremented automatically whenever `Match`/`MatchWithConntrackState` succeeds (and once more when a table's default rule fires, via `MatchDefaultRule`). Safe to read concurrently with evaluation; useful for exposing per-rule hit counts (e.g. to a metrics endpoint).

## Error handling

`rule.New`, `firecore.NewTable`, and `Engine.Evaluate` all return errors instead of panicking — check them. Common failure modes:

- `rule.New`: an invalid CIDR string (`WithSrcNet`/`WithDstNet`), or an unparsable regex (`WithPayload`).
- `firecore.NewTable`: failure constructing the internal default rule (mirrors `rule.New`'s failure modes for the default action).
- `Engine.Evaluate`: nil context/packet, a `WithJump` target chain that doesn't exist in the table, or (with conntrack enabled) a nil packet reaching the tracker.

## Worked example: jump, return, and pass across tables

Two tables: `classify` (lower `Order`, runs first) decides whether traffic is "trusted" and either accepts it early or lets `policy` (higher `Order`) make the final call.

```go
trustedSources := set.NewIPSet()
trustedSources.Add("192.0.2.0/24")

// classify: order 1
classify, _ := firecore.NewTable("classify", 1, rule.Drop)
classifyEntry := firecore.NewChain("entry")
classifyReview := firecore.NewChain("review")

jumpReview, _ := rule.New(rule.WithName("jump-review"), rule.WithJump("review"))
returnToEntry, _ := rule.New(rule.WithName("return-to-entry"), rule.WithAction(rule.Return))
passTrusted, _ := rule.New(
    rule.WithName("pass-trusted-app"),
    rule.WithSrcIPSet(trustedSources),
    rule.WithDstPort(8080),
    rule.WithProto(proto.TCP),
    rule.WithAction(rule.Pass),
)

classifyEntry.AddRule(jumpReview)   // 1. jump into "review"...
classifyEntry.AddRule(passTrusted) // 3. ...then, back in "entry", check pass-trusted-app
classifyReview.AddRule(returnToEntry) // 2. "review" unconditionally returns
classify.AddChain(classifyEntry)
classify.AddChain(classifyReview)
classify.SetEntryChain("entry")

// policy: order 2, runs only if classify didn't decide
policy, _ := firecore.NewTable("policy", 2, rule.Drop)
policyEntry := firecore.NewChain("entry")
allowTrustedApp, _ := rule.New(
    rule.WithName("allow-trusted-app"),
    rule.WithSrcIPSet(trustedSources),
    rule.WithDstPort(8080),
    rule.WithProto(proto.TCP),
    rule.WithAction(rule.Accept),
)
policyEntry.AddRule(allowTrustedApp)
policy.AddChain(policyEntry)
policy.SetEntryChain("entry")

engine := firecore.New()
engine.AddTable(classify)
engine.AddTable(policy)

result, _ := engine.Evaluate(eval.New(packet.New(
    packet.WithSrcAddr("192.0.2.25"),
    packet.WithDstAddr("198.51.100.10"),
    packet.WithProto(proto.TCP),
    packet.WithSrcPort(45000),
    packet.WithDstPort(8080),
)))

// result.Verdict == Accept, decided by policy's allow-trusted-app.
// result.Trace, in order:
//   jump-review      (classify/entry: jumps into review)
//   return-to-entry  (classify/review: returns immediately)
//   pass-trusted-app (classify/entry, resumed after the jump: matches, Pass)
//   allow-trusted-app (policy/entry: matches, Accept — final verdict)
```

This demonstrates all four control-flow actions in one pass: `Jump` transfers control, `Return` bounces it back to the call site, `Pass` moves the packet on to the next table instead of deciding, and `Accept` in that next table finally decides. See `base_ext_test.go` and `payload_ext_test.go` at the repository root for this and other complete, runnable scenarios (stateful established-flow shortcuts, named sets, payload regex matching, and default-rule fallthrough).
