// Use Criterion dependency for benchmarking
use criterion::{criterion_group, criterion_main, Criterion};
// Use standard library dependencies
use std::time::Duration;

mod bulletproof_mimc_bench;
mod snark_mimc_bench;
mod stark_mimc_bench;

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(100).measurement_time(Duration::from_secs(20));
    targets = bulletproof_mimc_bench::benchmark, snark_mimc_bench::benchmark, stark_mimc_bench::benchmark
}
criterion_main!(benches);
