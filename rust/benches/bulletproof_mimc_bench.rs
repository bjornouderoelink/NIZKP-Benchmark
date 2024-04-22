// Use Criterion dependency for benchmarking
use criterion::{black_box, Criterion};
// Use standard library dependencies
use rand::{rngs::StdRng, SeedableRng};
// Use Bulletproof dependencies
use bulletproofs::{BulletproofGens, PedersenGens};
use merlin::Transcript;
// Use the MiMC hash crate and code
use nizkp_benchmark::hash::mimc::{self, bulletproof};

const GENS_CAPACITY: usize = (mimc::MIMC_ROUNDS + 1) * 2;

// Benchmarks the Bulletproof MiMC hash
pub fn benchmark(c: &mut Criterion) {
    // One-time setup code goes here
    // Define a source of randomness
    let mut rng: StdRng = SeedableRng::from_seed(mimc::RANDOMNESS_SEED);

    // Generate the MiMC round constants
    let constants = (0..mimc::MIMC_ROUNDS)
        .map(|_| curve25519_dalek_ng::scalar::Scalar::random(&mut rng))
        .collect::<Vec<_>>();

    // Define the generators for the Pedersen commitments
    let pc_gens = PedersenGens::default();
    // Define the generators for the Bulletproofs
    let bp_gens = BulletproofGens::new(GENS_CAPACITY, 1);

    // Generate a random preimage
    let xl = curve25519_dalek_ng::scalar::Scalar::random(&mut rng);
    let xr = curve25519_dalek_ng::scalar::Scalar::random(&mut rng);

    // Compute the MiMC hash image
    let image = bulletproof::mimc(&xl, &xr, mimc::MIMC_ROUNDS, &constants);

    // Create the proof including commitments
    let (proof, commitments) = {
        let mut prover_transcript = Transcript::new(b"MiMC");
        let mut prover = bulletproofs::r1cs::Prover::new(&pc_gens, &mut prover_transcript);

        let (com_l, var_l) =
            prover.commit(xl, curve25519_dalek_ng::scalar::Scalar::random(&mut rng));
        let (com_r, var_r) =
            prover.commit(xr, curve25519_dalek_ng::scalar::Scalar::random(&mut rng));
        let left_alloc_scalar = bulletproof::AllocatedScalar {
            variable: var_l,
            assignment: Some(xl),
        };
        let right_alloc_scalar = bulletproof::AllocatedScalar {
            variable: var_r,
            assignment: Some(xr),
        };

        assert!(bulletproof::mimc_gadget(
            &mut prover,
            left_alloc_scalar,
            right_alloc_scalar,
            mimc::MIMC_ROUNDS,
            &constants,
            &image
        )
        .is_ok());

        (prover.prove(&bp_gens).unwrap(), (com_l, com_r))
    };

    // Get metrics from the commitments
    let runtime_commitments_size_bytes = std::mem::size_of_val(&commitments);
    let serilized_commitments_size_bytes = commitments.0 .0.len() + commitments.1 .0.len();
    println!(
        "Bulletproof commitment metrics: \n\tSize runtime (bytes): {} \n\tSize serialized (bytes): {}",
        runtime_commitments_size_bytes, serilized_commitments_size_bytes
    );

    // Get metrics from the proof
    let runtime_proof_size_bytes = std::mem::size_of_val(&proof);
    let serilized_proof_size_bytes = proof.serialized_size();
    println!(
        "Bulletproof proof metrics: \n\tSize runtime (bytes): {} \n\tSize serialized (bytes): {} \n\tSecurity level (bits): {} conjectured, {} proven",
        runtime_proof_size_bytes, serilized_proof_size_bytes, "?", "?"
    );

    let mut group = c.benchmark_group("bulletproof");

    group.bench_function("proof", |b| {
        // Per-sample (note that a sample can be many iterations) setup goes here
        b.iter(|| {
            // Measured code goes here
            let mut prover_transcript = Transcript::new(b"MiMC");
            let mut prover = bulletproofs::r1cs::Prover::new(&pc_gens, &mut prover_transcript);

            let (com_l, var_l) =
                prover.commit(xl, curve25519_dalek_ng::scalar::Scalar::random(&mut rng));
            let (com_r, var_r) =
                prover.commit(xr, curve25519_dalek_ng::scalar::Scalar::random(&mut rng));
            let left_alloc_scalar = bulletproof::AllocatedScalar {
                variable: var_l,
                assignment: Some(xl),
            };
            let right_alloc_scalar = bulletproof::AllocatedScalar {
                variable: var_r,
                assignment: Some(xr),
            };

            assert!(bulletproof::mimc_gadget(
                &mut prover,
                left_alloc_scalar,
                right_alloc_scalar,
                mimc::MIMC_ROUNDS,
                &constants,
                &image
            )
            .is_ok());

            black_box((prover.prove(&bp_gens).unwrap(), (com_l, com_r)))
        });
    });

    group.bench_function("verification", |b| {
        // Per-sample (note that a sample can be many iterations) setup goes here
        b.iter(|| {
            // Measured code goes here
            let mut verifier_transcript = Transcript::new(b"MiMC");
            let mut verifier = bulletproofs::r1cs::Verifier::new(&mut verifier_transcript);

            let var_l = verifier.commit(commitments.0);
            let var_r = verifier.commit(commitments.1);
            let left_alloc_scalar = bulletproof::AllocatedScalar {
                variable: var_l,
                assignment: None,
            };
            let right_alloc_scalar = bulletproof::AllocatedScalar {
                variable: var_r,
                assignment: None,
            };

            assert!(bulletproof::mimc_gadget(
                &mut verifier,
                left_alloc_scalar,
                right_alloc_scalar,
                mimc::MIMC_ROUNDS,
                &constants,
                &image
            )
            .is_ok());

            black_box(assert!(verifier.verify(&proof, &pc_gens, &bp_gens).is_ok()))
        });
    });
}
