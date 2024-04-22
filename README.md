# NIZKP-Benchmark
This repository contains the benchmark for the zk-SNARK, zk-STARK, and Bulletproof non-interactive zero-knowledge proof (NIZKP) protocols.
It implements an application that is as equivalent as possible for all three protocols. This allows a relatively fair performance comparison between the three protocols.

**IMPORTANT NOTE**: The code in this repository is meant for research purposes only. It was designed to benchmark the performance characteristics of each protocol for an equivalent application, _not_ to provide guarantees on the functionality or security of the implementations. As such, the code in this repository may contain bugs or security vulnerabilities. **Do not use the code in this repository for anything other than research purposes or experimentation!**

Also, this is not the cleanest codebase you'll ever see. Since we only needed to obtain the performance metrics by benchmarking everything once, it was faster to perform some configuration changes manually between runs than to spend a lot of time to automate everything following best practices.


## Repository layout
The layout of this repository is split in two parts, one for each of the used programming languages.

The `rust/src/hash/mimc` directory contains the MiMC hash application implementation for of each of the three NIZKP protocols in separate files.
The `rust/benches` directory contains the actual benchmark code for each protocol. 

The `go/internal/hash` directory contains a MiMC hash application implementation and corresponding benchmark test file for the zk-SNARK protocol only. The intention for this implementation was to enable a comparison on the differences between a Rust and Go implementation of the same protocol.
The `go/internal/zksig` directory contains the implementations for the experimental zero-knowledge signature application idea using EdDSA and ECDSA respectively, which were based on the [zkAttest paper](https://eprint.iacr.org/2021/1183). This application is included solely for reference purposes, it was not benchmarked and therefore the implementations were not entirely completed.


## Installation
### Rust
Ensure that [Rust and Cargo are installed](https://www.rust-lang.org/tools/install).
We performed the benchmark using Rustc and Cargo version 1.76.0.

### Go
Ensure that [Go is installed](https://go.dev/doc/install).
We performed the benchmark using Go version 1.22.0.


## Running the benchmarks
### Rust
From the `rust` directory, run:
```sh
cargo bench
```

### Go
From the `go` directory, run:
```sh
go test -bench . ./internal/hash/.
```
We can also add the `-benchmem` flag to the `go test` command above to output memory usage and allocation metrics as well.


## Running the code
The code can also be run separately from the benchmarks, e.g. to obtain just the metrics output. To do so, use the following commands.

### Rust
From the `rust` directory, run:
```sh
cargo run
```

### Go
From the `go` directory, run:
```sh
go run main.go
```
