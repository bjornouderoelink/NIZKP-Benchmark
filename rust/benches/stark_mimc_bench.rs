// Use Criterion dependency for benchmarking
use criterion::{black_box, Criterion};
// Use standard library dependencies
use rand::{rngs::StdRng, RngCore, SeedableRng};
// Use zkSTARK dependencies
#[allow(unused_imports)]
use winterfell::crypto::hashers::{Blake3_192, Blake3_256, Sha3_256};
use winterfell::{
    crypto::DefaultRandomCoin,
    math::{fields::f128::BaseElement, FieldElement},
    FieldExtension, ProofOptions, Prover,
};
// Use the MiMC hash crate and code
use nizkp_benchmark::hash::mimc::{self, stark};

type Hasher = Blake3_256<BaseElement>;
const NUM_QUERIES: usize = 42; // must not be > 255
const BLOWUP_FACTOR: usize = 8; // must be a power of two and must not be > 128
const GRINDING_FACTOR: u32 = 16; // must not be > 32
const FIELD_EXTENSION: FieldExtension = FieldExtension::None;
const FRI_FOLDING_FACTOR: usize = 8; // must be 2, 4, 8, or 16
const FRI_REMAINDER_MAX_DEGREE: usize = 31; // must be a power of two -1 and must not be > 255

// Benchmarks the zkSTARK MiMC hash
pub fn benchmark(c: &mut Criterion) {
    // One-time setup code goes here
    let options = ProofOptions::new(
        NUM_QUERIES,
        BLOWUP_FACTOR,
        GRINDING_FACTOR,
        FIELD_EXTENSION,
        FRI_FOLDING_FACTOR,
        FRI_REMAINDER_MAX_DEGREE,
    );
    let acceptable_options = winterfell::AcceptableOptions::OptionSet(vec![options.clone()]);

    // Define a source of randomness
    let mut rng: StdRng = SeedableRng::from_seed(mimc::RANDOMNESS_SEED);

    // Generate the MiMC round constants
    let mut round_constants = [BaseElement::ZERO; mimc::MIMC_ROUNDS];
    for i in 0..round_constants.len() {
        round_constants[i] = BaseElement::new(rng.next_u64() as u128);
    }

    // Generate a random preimage
    let rand_xl: u64 = rng.next_u64();
    let xl = BaseElement::new(rand_xl as u128);
    let rand_xr: u64 = rng.next_u64();
    let xr = BaseElement::new(rand_xr as u128);

    // Compute the MiMC hash image
    let image = stark::mimc(xl, xr, &round_constants);

    // Create the proof
    let proof = {
        let prover = stark::MiMCProver::<Hasher>::new(options.clone());

        let trace = prover.build_trace(xl, xr, &round_constants);
        prover.prove(trace).unwrap()
    };
    let proof_ref = &proof;

    // Get metrics from the proof
    let runtime_proof_size_bytes = std::mem::size_of_val(&proof);
    let serilized_proof_size_bytes = proof.to_bytes().len();
    let proven_security_level = proof.security_level::<Hasher>(false);
    let conjectured_security_level = proof.security_level::<Hasher>(true);

    println!(
        "STARK proof metrics: \n\tSize runtime (bytes): {} \n\tSize serialized (bytes): {} \n\tSecurity level (bits): {} conjectured, {} proven",
        runtime_proof_size_bytes, serilized_proof_size_bytes, conjectured_security_level, proven_security_level
    );

    let mut group = c.benchmark_group("stark");

    group.bench_function("proof", |b| {
        // Per-sample (note that a sample can be many iterations) setup goes here
        b.iter(|| {
            // Measured code goes here
            let proof = {
                let prover = stark::MiMCProver::<Hasher>::new(options.clone());

                let trace = prover.build_trace(xl, xr, &round_constants);
                prover.prove(trace).unwrap()
            };
            black_box(proof)
        });
    });

    group.bench_function("verification", |b| {
        // Per-sample (note that a sample can be many iterations) setup goes here
        b.iter(|| {
            // Measured code goes here
            let pub_inputs = stark::PublicInputs {
                xl,
                xr,
                result: image,
                round_constants,
            };
            let proof = proof_ref.clone();
            black_box(assert!(winterfell::verify::<
                stark::MiMCAir,
                Hasher,
                DefaultRandomCoin<Hasher>,
            >(
                proof, pub_inputs, &acceptable_options,
            )
            .is_ok()))
        });
    });
}
