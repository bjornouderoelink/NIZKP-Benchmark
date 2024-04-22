// Use Criterion dependency for benchmarking
use criterion::{black_box, Criterion};
// Use standard library dependencies
use rand::{rngs::StdRng, SeedableRng};
// Use zkSNARK dependencies
use bellman::groth16::{
    create_random_proof, generate_random_parameters, prepare_verifying_key, verify_proof,
};
use bls12_381::Bls12;
use ff::Field;
// Use the MiMC hash crate and code
use nizkp_benchmark::hash::mimc::{self, snark};

// Benchmarks the zkSNARK MiMC hash
pub fn benchmark(c: &mut Criterion) {
    // One-time setup code goes here
    // Define a source of randomness
    let mut rng: StdRng = SeedableRng::from_seed(mimc::RANDOMNESS_SEED);

    // Generate the MiMC round constants
    let constants = (0..mimc::MIMC_ROUNDS)
        .map(|_| bls12_381::Scalar::random(&mut rng))
        .collect::<Vec<_>>();

    // Generate the Common Reference String (CRS)
    let crs = {
        let circuit = snark::MiMCCircuit {
            xl: None,
            xr: None,
            constants: &constants,
        };

        generate_random_parameters::<Bls12, _, _>(circuit, &mut rng).unwrap()
    };

    // Prepare the verification key (for proof verification)
    let pvk = prepare_verifying_key(&crs.vk);

    // Generate a random preimage
    let xl = bls12_381::Scalar::random(&mut rng);
    let xr = bls12_381::Scalar::random(&mut rng);

    // Compute the MiMC hash image
    let image = snark::mimc(xl, xr, &constants);

    // Create a groth16 proof with the defined parameters
    let proof = {
        let circuit = snark::MiMCCircuit {
            xl: Some(xl),
            xr: Some(xr),
            constants: &constants,
        };

        create_random_proof(circuit, &crs, &mut rng).unwrap()
    };

    // Get metrics for the CRS
    let runtime_crs_size_bytes = std::mem::size_of_val(&crs);
    let serialized_crs_size_bytes_without_verifying_key_compressed = 0
        + crs
            .h
            .as_ref()
            .iter()
            .fold(0, |acc, x| acc + x.to_compressed().len())
        + crs
            .l
            .as_ref()
            .iter()
            .fold(0, |acc, x| acc + x.to_compressed().len())
        + crs
            .a
            .as_ref()
            .iter()
            .fold(0, |acc, x| acc + x.to_compressed().len())
        + crs
            .b_g1
            .as_ref()
            .iter()
            .fold(0, |acc, x| acc + x.to_compressed().len())
        + crs
            .b_g2
            .as_ref()
            .iter()
            .fold(0, |acc, x| acc + x.to_compressed().len());
    let serialized_verification_key_size_bytes_compressed = 0
        + crs.vk.alpha_g1.to_compressed().len()
        + crs.vk.beta_g1.to_compressed().len()
        + crs.vk.beta_g2.to_compressed().len()
        + crs.vk.gamma_g2.to_compressed().len()
        + crs.vk.delta_g1.to_compressed().len()
        + crs.vk.delta_g2.to_compressed().len()
        + crs
            .vk
            .ic
            .iter()
            .fold(0, |acc, x| acc + x.to_compressed().len());
    println!(
        "SNARK CRS metrics: \n\tSize runtime (bytes): {} \n\tSize serialized without verification key (bytes): {} compressed \n\tSize serialized verification key (bytes): {} compressed",
        runtime_crs_size_bytes, serialized_crs_size_bytes_without_verifying_key_compressed, serialized_verification_key_size_bytes_compressed
    );

    // Get metrics from the proof
    let runtime_proof_size_bytes = std::mem::size_of_val(&proof);
    let serilized_proof_size_bytes_compressed = proof.a.to_compressed().len()
        + proof.b.to_compressed().len()
        + proof.c.to_compressed().len();
    // NOTE: uncompressed size is twice the compressed size.
    println!(
        "SNARK proof metrics: \n\tSize runtime (bytes): {} \n\tSize serialized (bytes): {} compressed \n\tSecurity level (bits): {} conjectured, {} proven",
        runtime_proof_size_bytes, serilized_proof_size_bytes_compressed, "?", "?"
    );

    let mut group = c.benchmark_group("snark");

    // Benchmark setup time
    group.bench_function("setup", |b| {
        // Per-sample (note that a sample can be many iterations) setup goes here
        b.iter(|| {
            // Measured code goes here
            let circuit = snark::MiMCCircuit {
                xl: None,
                xr: None,
                constants: &constants,
            };
            let crs = generate_random_parameters::<Bls12, _, _>(circuit, &mut rng).unwrap();
            black_box(prepare_verifying_key(&crs.vk))
        });
    });

    // Benchmark proof time
    group.bench_function("proof", |b| {
        // Per-sample (note that a sample can be many iterations) setup goes here
        b.iter(|| {
            // Measured code goes here
            let circuit = snark::MiMCCircuit {
                xl: Some(xl),
                xr: Some(xr),
                constants: &constants,
            };
            black_box(create_random_proof(circuit, &crs, &mut rng))
        });
    });

    // Benchmark verification time
    group.bench_function("verification", |b| {
        // Per-sample (note that a sample can be many iterations) setup goes here
        b.iter(|| {
            // Measured code goes here
            let verification_result = verify_proof(&pvk, &proof, &[image]);
            black_box(assert!(verification_result.is_ok()));
        });
    });
}
