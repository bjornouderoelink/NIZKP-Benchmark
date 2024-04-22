// The code in this file is adapted from https://github.com/zkcrypto/bellman/blob/main/tests/mimc.rs

use super::*;
use bellman::{
    groth16::{
        create_random_proof, generate_random_parameters, prepare_verifying_key, verify_proof,
    },
    Circuit, ConstraintSystem, SynthesisError,
};
use bls12_381::{Bls12, Scalar};
use ff::{Field, PrimeField};
use rand::{rngs::StdRng, SeedableRng};
use std::time::{Duration, Instant};

pub fn run() {
    let mimc_rounds = MIMC_ROUNDS;

    // Define a source of randomness
    let mut rng: StdRng = SeedableRng::from_seed(RANDOMNESS_SEED);

    // Generate the MiMC round constants
    let constants = (0..mimc_rounds)
        .map(|_| Scalar::random(&mut rng))
        .collect::<Vec<_>>();

    // Generate the Common Reference String (CRS)
    let crs = {
        let circuit = MiMCCircuit {
            xl: None,
            xr: None,
            constants: &constants,
        };

        generate_random_parameters::<Bls12, _, _>(circuit, &mut rng).unwrap()
    };

    // Prepare the verification key (for proof verification)
    let pvk = prepare_verifying_key(&crs.vk);

    // Generate a random preimage
    let xl = Scalar::random(&mut rng);
    let xr = Scalar::random(&mut rng);

    // Compute the MiMC hash image
    let image = mimc(xl, xr, &constants);

    // Create a groth16 proof with the defined parameters
    let proof = {
        let circuit = MiMCCircuit {
            xl: Some(xl),
            xr: Some(xr),
            constants: &constants,
        };

        create_random_proof(circuit, &crs, &mut rng).unwrap()
    };

    // Verify that the proof is valid
    let verification_result = verify_proof(&pvk, &proof, &[image]);
    assert!(verification_result.is_ok());

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
        "CRS metrics: \n\tSize runtime (bytes): {} \n\tSize serialized without verification key (bytes): {} compressed \n\tSize serialized verification key (bytes): {} compressed",
        runtime_crs_size_bytes, serialized_crs_size_bytes_without_verifying_key_compressed, serialized_verification_key_size_bytes_compressed
    );

    // Get metrics from the proof
    let runtime_proof_size_bytes = std::mem::size_of_val(&proof);
    let serilized_proof_size_bytes_compressed = proof.a.to_compressed().len()
        + proof.b.to_compressed().len()
        + proof.c.to_compressed().len();
    // NOTE: uncompressed size is twice the compressed size.
    println!(
        "Proof metrics: \n\tSize runtime (bytes): {} \n\tSize serialized (bytes): {} compressed \n\tSecurity level (bits): {} conjectured, {} proven",
        runtime_proof_size_bytes, serilized_proof_size_bytes_compressed, "?", "?"
    );
}

#[test]
fn test_run() {
    run()
}

#[allow(dead_code)]
fn benchmark(mimc_rounds: usize, samples: u32) {
    // Define a source of randomness
    let mut rng: StdRng = SeedableRng::from_seed(RANDOMNESS_SEED);

    // Generate the MiMC round constants
    let constants = (0..mimc_rounds)
        .map(|_| Scalar::random(&mut rng))
        .collect::<Vec<_>>();

    // Generate the Common Reference String (CRS)
    let crs = {
        let circuit = MiMCCircuit {
            xl: None,
            xr: None,
            constants: &constants,
        };

        generate_random_parameters::<Bls12, _, _>(circuit, &mut rng).unwrap()
    };

    // Prepare the verification key (for proof verification)
    let pvk = prepare_verifying_key(&crs.vk);

    // Generate a random preimage
    let xl = Scalar::random(&mut rng);
    let xr = Scalar::random(&mut rng);

    // Compute the MiMC hash image
    let image = mimc(xl, xr, &constants);

    let mut total_proving = Duration::new(0, 0);
    let mut total_verifying = Duration::new(0, 0);
    for _ in 0..SAMPLES {
        let start = Instant::now();
        // Create a groth16 proof with the defined parameters
        let proof = {
            let circuit = MiMCCircuit {
                xl: Some(xl),
                xr: Some(xr),
                constants: &constants,
            };

            create_random_proof(circuit, &crs, &mut rng).unwrap()
        };
        total_proving += start.elapsed();

        // Verify that the proof is valid
        let start = Instant::now();
        let verification_result = verify_proof(&pvk, &proof, &[image]);
        assert!(verification_result.is_ok());
        total_verifying += start.elapsed();
    }

    let proving_avg = total_proving / samples;
    let proving_avg =
        proving_avg.subsec_nanos() as f64 / 1_000_000_000f64 + (proving_avg.as_secs() as f64);
    println!(
        "Average proving time ({} samples): {:?} seconds",
        samples, proving_avg
    );

    let verifying_avg = total_verifying / samples;
    let verifying_avg =
        verifying_avg.subsec_nanos() as f64 / 1_000_000_000f64 + (verifying_avg.as_secs() as f64);
    println!(
        "Average verifying time ({} samples): {:?} seconds",
        samples, verifying_avg
    );
}

#[test]
fn test_benchmark() {
    benchmark(MIMC_ROUNDS, SAMPLES)
}

// This is an implementation of MiMC, specifically a
// variant named `LongsightF322p3` for BLS12-381.
pub fn mimc<S: PrimeField>(mut xl: S, mut xr: S, constants: &[S]) -> S {
    for c in constants {
        let mut tmp1 = xl;
        tmp1.add_assign(c);
        let mut tmp2 = tmp1.cube();
        tmp2.add_assign(&xr);
        xr = xl;
        xl = tmp2;
    }

    xl
}

// This is the circuit for proving knowledge of the
// preimage of a MiMC hash invocation.
#[allow(clippy::upper_case_acronyms)]
pub struct MiMCCircuit<'a, S: PrimeField> {
    pub xl: Option<S>,
    pub xr: Option<S>,
    pub constants: &'a [S],
}

// Our circuit implements this `Circuit` trait which
// is used during paramgen and proving in order to
// synthesize the constraint system.
impl<'a, S: PrimeField> Circuit<S> for MiMCCircuit<'a, S> {
    fn synthesize<CS: ConstraintSystem<S>>(self, cs: &mut CS) -> Result<(), SynthesisError> {
        assert_eq!(self.constants.len(), MIMC_ROUNDS);

        // Allocate the first component of the preimage.
        let mut xl_value = self.xl;
        let mut xl = cs.alloc(
            || "preimage xl",
            || xl_value.ok_or(SynthesisError::AssignmentMissing),
        )?;

        // Allocate the second component of the preimage.
        let mut xr_value = self.xr;
        let mut xr = cs.alloc(
            || "preimage xr",
            || xr_value.ok_or(SynthesisError::AssignmentMissing),
        )?;

        for i in 0..MIMC_ROUNDS {
            // xL, xR := xR + (xL + Ci)^3, xL
            let cs = &mut cs.namespace(|| format!("round {}", i));

            // tmp = (xL + Ci)^2
            let tmp_value = xl_value.map(|mut e| {
                e.add_assign(&self.constants[i]);
                e.square()
            });
            let tmp = cs.alloc(
                || "tmp",
                || tmp_value.ok_or(SynthesisError::AssignmentMissing),
            )?;

            cs.enforce(
                || "tmp = (xL + Ci)^2",
                |lc| lc + xl + (self.constants[i], CS::one()),
                |lc| lc + xl + (self.constants[i], CS::one()),
                |lc| lc + tmp,
            );

            // new_xL = xR + (xL + Ci)^3
            // new_xL = xR + tmp * (xL + Ci)
            // new_xL - xR = tmp * (xL + Ci)
            let new_xl_value = xl_value.map(|mut e| {
                e.add_assign(&self.constants[i]);
                e.mul_assign(&tmp_value.unwrap());
                e.add_assign(&xr_value.unwrap());
                e
            });

            let new_xl = if i == (MIMC_ROUNDS - 1) {
                // This is the last round, xL is our image and so
                // we allocate a public input.
                cs.alloc_input(
                    || "image",
                    || new_xl_value.ok_or(SynthesisError::AssignmentMissing),
                )?
            } else {
                cs.alloc(
                    || "new_xl",
                    || new_xl_value.ok_or(SynthesisError::AssignmentMissing),
                )?
            };

            cs.enforce(
                || "new_xL = xR + (xL + Ci)^3",
                |lc| lc + tmp,
                |lc| lc + xl + (self.constants[i], CS::one()),
                |lc| lc + new_xl - xr,
            );

            // xR = xL
            xr = xl;
            xr_value = xl_value;

            // xL = new_xL
            xl = new_xl;
            xl_value = new_xl_value;
        }

        Ok(())
    }
}
