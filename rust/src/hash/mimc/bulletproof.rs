// The code in this file is adapted from https://github.com/lovesh/bulletproofs-r1cs-gadgets/blob/master/src/gadget_mimc.rs

use super::*;
use bulletproofs::{
    r1cs::{ConstraintSystem, LinearCombination, Prover, R1CSError, Variable, Verifier},
    BulletproofGens, PedersenGens,
};
use curve25519_dalek_ng::scalar::Scalar;
use merlin::Transcript;
use rand::{rngs::StdRng, SeedableRng};
use std::time::{Duration, Instant};

// GENS_CAPACITY limits the max number of MIMC_ROUNDS rounds possible
const GENS_CAPACITY: usize = (MIMC_ROUNDS + 1) * 2;

pub fn run() {
    let mimc_rounds = MIMC_ROUNDS;

    // Define a source of randomness
    let mut rng: StdRng = SeedableRng::from_seed(RANDOMNESS_SEED);

    // Generate the MiMC round constants
    let constants = (0..mimc_rounds)
        .map(|_| Scalar::random(&mut rng))
        .collect::<Vec<_>>();

    // Define the generators for the Pedersen commitments
    let pc_gens = PedersenGens::default();
    // Define the generators for the Bulletproofs
    let bp_gens = BulletproofGens::new(GENS_CAPACITY, 1);

    // Generate a random preimage
    let xl = Scalar::random(&mut rng);
    let xr = Scalar::random(&mut rng);

    // Compute the MiMC hash image
    let image = mimc(&xl, &xr, mimc_rounds, &constants);

    // Create the proof including commitments
    let (proof, commitments) = {
        let mut prover_transcript = Transcript::new(b"MiMC");
        let mut prover = Prover::new(&pc_gens, &mut prover_transcript);

        let (com_l, var_l) = prover.commit(xl, Scalar::random(&mut rng));
        let (com_r, var_r) = prover.commit(xr, Scalar::random(&mut rng));
        let left_alloc_scalar = AllocatedScalar {
            variable: var_l,
            assignment: Some(xl),
        };
        let right_alloc_scalar = AllocatedScalar {
            variable: var_r,
            assignment: Some(xr),
        };

        assert!(mimc_gadget(
            &mut prover,
            left_alloc_scalar,
            right_alloc_scalar,
            mimc_rounds,
            &constants,
            &image
        )
        .is_ok());

        println!(
            "MiMC hash with {} rounds has the following prover metrics: {:?}",
            &mimc_rounds,
            &prover.metrics()
        );

        (prover.prove(&bp_gens).unwrap(), (com_l, com_r))
    };

    // Verify that the proof is valid
    let verification_result = {
        let mut verifier_transcript = Transcript::new(b"MiMC");
        let mut verifier = Verifier::new(&mut verifier_transcript);

        let var_l = verifier.commit(commitments.0);
        let var_r = verifier.commit(commitments.1);
        let left_alloc_scalar = AllocatedScalar {
            variable: var_l,
            assignment: None,
        };
        let right_alloc_scalar = AllocatedScalar {
            variable: var_r,
            assignment: None,
        };

        assert!(mimc_gadget(
            &mut verifier,
            left_alloc_scalar,
            right_alloc_scalar,
            mimc_rounds,
            &constants,
            &image
        )
        .is_ok());

        println!(
            "MiMC hash with {} rounds has the following verifier metrics: {:?}",
            &mimc_rounds,
            &verifier.metrics()
        );

        verifier.verify(&proof, &pc_gens, &bp_gens)
    };

    assert!(verification_result.is_ok());

    // Get metrics from the proof
    let runtime_proof_size_bytes = std::mem::size_of_val(&proof);
    let serilized_proof_size_bytes = proof.serialized_size();
    println!(
        "Proof metrics: \n\tSize runtime (bytes): {} \n\tSize serialized (bytes): {} \n\tSecurity level (bits): {} conjectured, {} proven",
        runtime_proof_size_bytes, serilized_proof_size_bytes, "?", "?"
    );

    // Get metrics from the commitments
    let runtime_commitments_size_bytes = std::mem::size_of_val(&commitments);
    let serilized_commitments_size_bytes = commitments.0 .0.len() + commitments.1 .0.len();
    println!(
        "Commitment metrics: \n\tSize runtime (bytes): {} \n\tSize serialized (bytes): {}",
        runtime_commitments_size_bytes, serilized_commitments_size_bytes
    );
}

#[test]
fn test_run() {
    run();
}

#[allow(dead_code)]
fn benchmark(mimc_rounds: usize, samples: u32) {
    // Define a source of randomness
    let mut rng: StdRng = SeedableRng::from_seed(RANDOMNESS_SEED);

    // Generate the MiMC round constants
    let constants = (0..mimc_rounds)
        .map(|_| Scalar::random(&mut rng))
        .collect::<Vec<_>>();

    // Define the generators for the Pedersen commitments
    let pc_gens = PedersenGens::default();
    // Define the generators for the Bulletproofs
    let bp_gens = BulletproofGens::new(2048, 1);

    // Generate a random preimage
    let xl = Scalar::random(&mut rng);
    let xr = Scalar::random(&mut rng);

    let mut total_proving_time = Duration::new(0, 0);
    let mut total_verifying_time = Duration::new(0, 0);
    for _ in 0..samples {
        // Compute the MiMC hash image
        let image = mimc(&xl, &xr, mimc_rounds, &constants);

        // Create the proof including commitments
        let (proof, commitments) = {
            let mut prover_transcript = Transcript::new(b"MiMC");
            let mut prover = Prover::new(&pc_gens, &mut prover_transcript);

            let start = Instant::now();

            let (com_l, var_l) = prover.commit(xl, Scalar::random(&mut rng));
            let (com_r, var_r) = prover.commit(xr, Scalar::random(&mut rng));
            let left_alloc_scalar = AllocatedScalar {
                variable: var_l,
                assignment: Some(xl),
            };
            let right_alloc_scalar = AllocatedScalar {
                variable: var_r,
                assignment: Some(xr),
            };

            assert!(mimc_gadget(
                &mut prover,
                left_alloc_scalar,
                right_alloc_scalar,
                mimc_rounds,
                &constants,
                &image
            )
            .is_ok());

            let proof = prover.prove(&bp_gens).unwrap();
            total_proving_time += start.elapsed();

            (proof, (com_l, com_r))
        };

        // Verify that the proof is valid
        let verification_result = {
            let mut verifier_transcript = Transcript::new(b"MiMC");
            let mut verifier = Verifier::new(&mut verifier_transcript);

            let var_l = verifier.commit(commitments.0);
            let var_r = verifier.commit(commitments.1);
            let left_alloc_scalar = AllocatedScalar {
                variable: var_l,
                assignment: None,
            };
            let right_alloc_scalar = AllocatedScalar {
                variable: var_r,
                assignment: None,
            };

            let start = Instant::now();
            assert!(mimc_gadget(
                &mut verifier,
                left_alloc_scalar,
                right_alloc_scalar,
                mimc_rounds,
                &constants,
                &image
            )
            .is_ok());

            let verification_result = verifier.verify(&proof, &pc_gens, &bp_gens);
            total_verifying_time += start.elapsed();

            verification_result
        };

        assert!(verification_result.is_ok());
    }

    let proving_avg = total_proving_time / samples;
    let proving_avg =
        proving_avg.subsec_nanos() as f64 / 1_000_000_000f64 + (proving_avg.as_secs() as f64);
    println!(
        "Average proving time ({} samples): {:?} seconds",
        samples, proving_avg
    );

    let verifying_avg = total_verifying_time / samples;
    let verifying_avg =
        verifying_avg.subsec_nanos() as f64 / 1_000_000_000f64 + (verifying_avg.as_secs() as f64);
    println!(
        "Average verifying time ({} samples): {:?} seconds",
        samples, verifying_avg
    );
}

#[test]
fn test_benchmark() {
    benchmark(MIMC_ROUNDS, SAMPLES);
}

pub fn mimc(xl: &Scalar, xr: &Scalar, mimc_rounds: usize, constants: &[Scalar]) -> Scalar {
    let mut xl = xl.clone();
    let mut xr = xr.clone();

    for i in 0..mimc_rounds {
        let tmp1 = xl + constants[i];
        let mut tmp2 = (tmp1 * tmp1) * tmp1;
        tmp2 += xr;
        xr = xl;
        xl = tmp2;
    }

    xl
}

pub fn mimc_gadget<CS: ConstraintSystem>(
    cs: &mut CS,
    left: AllocatedScalar,
    right: AllocatedScalar,
    mimc_rounds: usize,
    mimc_constants: &[Scalar],
    image: &Scalar,
) -> Result<(), R1CSError> {
    let res_v = mimc_hash_2::<CS>(
        cs,
        left.variable.into(),
        right.variable.into(),
        mimc_rounds,
        mimc_constants,
    )?;
    constrain_lc_with_scalar::<CS>(cs, res_v, image);
    Ok(())
}

pub fn mimc_hash_2<CS: ConstraintSystem>(
    cs: &mut CS,
    left: LinearCombination,
    right: LinearCombination,
    mimc_rounds: usize,
    mimc_constants: &[Scalar],
) -> Result<LinearCombination, R1CSError> {
    let mut left_v = left;
    let mut right_v = right;

    for j in 0..mimc_rounds {
        // xL, xR := xR + (xL + Ci)^3, xL
        //let cs = &mut cs.namespace(|| format!("mimc round {}", j));

        let const_lc: LinearCombination =
            vec![(Variable::One(), mimc_constants[j])].iter().collect();

        let left_plus_const: LinearCombination = left_v.clone() + const_lc;

        let (l, _, l_sqr) = cs.multiply(left_plus_const.clone(), left_plus_const);
        let (_, _, l_cube) = cs.multiply(l_sqr.into(), l.into());

        let tmp = LinearCombination::from(l_cube) + right_v;
        right_v = left_v;
        left_v = tmp;
    }
    Ok(left_v)
}

/// Represents a variable for quantity, along with its assignment.
#[derive(Copy, Clone, Debug)]
pub struct AllocatedQuantity {
    pub variable: Variable,
    pub assignment: Option<u64>,
}

#[derive(Copy, Clone, Debug)]
pub struct AllocatedScalar {
    pub variable: Variable,
    pub assignment: Option<Scalar>,
}

/// Constrain a linear combination to be equal to a scalar
pub fn constrain_lc_with_scalar<CS: ConstraintSystem>(
    cs: &mut CS,
    lc: LinearCombination,
    scalar: &Scalar,
) {
    cs.constrain(lc - LinearCombination::from(*scalar));
}
