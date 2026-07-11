firecore
========

firecore is a reusable Go library for firewall-style packet filtering. It models evaluation the way nftables/iptables do: ordered **tables** containing named **chains** of **rules**, with `accept`/`drop`/`pass`/`jump`/`return` control flow, connection-state tracking for new vs. established flows, per-rule packet counters, and a full trace of every rule a packet touched.

## Install

```sh
go get github.com/mazdakn/firecore
```

Requires Go 1.24+.

## Quick start

```go
package main

import (
	"fmt"

	firecore "github.com/mazdakn/firecore"
	"github.com/mazdakn/firecore/packet"
	"github.com/mazdakn/firecore/proto"
)

func main() {
	// A table's default rule fires when nothing in its entry chain decides.
	policy, err := firecore.NewTable("policy", 0, firecore.Drop)
	if err != nil {
		panic(err)
	}

	allowHTTP, err := firecore.NewRule(
		firecore.WithName("allow-http"),
		firecore.WithProto(proto.TCP),
		firecore.WithDstPort(80),
		firecore.WithAction(firecore.Accept),
	)
	if err != nil {
		panic(err)
	}

	entry := firecore.NewChain("entry")
	entry.AddRule(allowHTTP)
	policy.AddChain(entry)

	engine := firecore.New()
	engine.AddTable(policy)

	pkt := packet.New(
		packet.WithSrcAddr("10.0.0.1"),
		packet.WithDstAddr("1.1.1.1"),
		packet.WithProto(proto.TCP),
		packet.WithSrcPort(12345),
		packet.WithDstPort(80),
	)

	result, err := engine.Evaluate(pkt)
	if err != nil {
		panic(err)
	}

	fmt.Println(result.Verdict) // Accept
}
```

## Packages

| Package | Purpose |
|---|---|
| `firecore` (root) | `Engine`, `Table`, `Chain`, `Result`, `Rule`, `Action`, and the `With*` functional options used to build tables and match packets |
| `packet` | `Packet` — the metadata a rule matches against |
| `proto` | IP protocol numbers/names (tcp, udp, icmp, ...) |
| `port` | Port numbers, well-known names, and ranges |
| `set` | Named, reusable sets of IPs, ports, IP:port pairs, interfaces, and protocols |
| `conntrack` | Connection-state tracking (new vs. established) |
| `counter` | Atomic packet counters used by `Rule` |
| `payload` | Regex-based payload matching |

## Testing

```sh
make test
```

Runs `go vet`, `golangci-lint`, and `go test -race -cover` across all packages. Root-level tests are split between `package firecore` (internal, e.g. `firecore_test.go`, `table_test.go`) and `package firecore_test` (external, black-box tests named `*_ext_test.go`).
