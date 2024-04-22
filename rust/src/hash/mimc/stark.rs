use super::*;
use rand::{rngs::StdRng, RngCore, SeedableRng};
use std::{
    marker::PhantomData,
    time::{Duration, Instant},
    vec,
};
#[allow(unused_imports)]
use winterfell::crypto::hashers::{Blake3_192, Blake3_256, Sha3_256};
use winterfell::{
    crypto::{DefaultRandomCoin, ElementHasher},
    math::{fields::f128::BaseElement, FieldElement, ToElements},
    matrix::ColMatrix,
    Air, AirContext, Assertion, AuxTraceRandElements, ConstraintCompositionCoefficients,
    DefaultConstraintEvaluator, DefaultTraceLde, EvaluationFrame, FieldExtension, ProofOptions,
    Prover, StarkDomain, Trace, TraceInfo, TracePolyTable, TraceTable, TransitionConstraintDegree,
};

const TRACE_WIDTH: usize = 3;
// NOTE: the domain size is trace_length * options.blowup_factor, where the trace_length is lower for lower MIMC_ROUNDS.
// If the "number of values must be smaller than domain size" occurs we should increase the blowup_factor.
// A blowup_factor of 8 works for the mimimum number of MiMC rounds (8), while 4 is already enough for 16 rounds, etc.
const NUM_QUERIES: usize = 42; // must not be > 255
const BLOWUP_FACTOR: usize = 8; // must be a power of two and must not be > 128
const GRINDING_FACTOR: u32 = 16; // must not be > 32
const FIELD_EXTENSION: FieldExtension = FieldExtension::None;
const FRI_FOLDING_FACTOR: usize = 8; // must be 2, 4, 8, or 16
const FRI_REMAINDER_MAX_DEGREE: usize = 31; // must be a power of two -1 and must not be > 255

pub fn run() {
    let options = ProofOptions::new(
        NUM_QUERIES,
        BLOWUP_FACTOR,
        GRINDING_FACTOR,
        FIELD_EXTENSION,
        FRI_FOLDING_FACTOR,
        FRI_REMAINDER_MAX_DEGREE,
    );
    let acceptable_options = winterfell::AcceptableOptions::OptionSet(vec![options.clone()]);
    type Hasher = Blake3_256<BaseElement>;

    // Define a source of randomness
    let mut rng: StdRng = SeedableRng::from_seed(RANDOMNESS_SEED);

    // Generate the MiMC round constants
    let mut round_constants = [BaseElement::ZERO; MIMC_ROUNDS];
    for i in 0..round_constants.len() {
        round_constants[i] = BaseElement::new(rng.next_u64() as u128);
    }

    // Generate a random preimage
    let rand_xl: u64 = rng.next_u64();
    let xl = BaseElement::new(rand_xl as u128);
    let rand_xr: u64 = rng.next_u64();
    let xr = BaseElement::new(rand_xr as u128);

    // Compute the MiMC hash image
    let image = mimc(xl, xr, &round_constants);

    // Create the proof
    let proof = {
        let prover = MiMCProver::<Hasher>::new(options.clone());

        let trace = prover.build_trace(xl, xr, &round_constants);
        prover.prove(trace).unwrap()
    };

    // Get metrics from the proof before it is moved for verification
    let runtime_proof_size_bytes = std::mem::size_of_val(&proof);
    let serilized_proof_size_bytes = proof.to_bytes().len();
    let proven_security_level = proof.security_level::<Hasher>(false);
    let conjectured_security_level = proof.security_level::<Hasher>(true);

    // Verify that the proof is valid
    let verification_result = {
        let pub_inputs = PublicInputs {
            xl,
            xr,
            result: image,
            round_constants,
        };

        winterfell::verify::<MiMCAir, Hasher, DefaultRandomCoin<Hasher>>(
            proof,
            pub_inputs,
            &acceptable_options,
        )
    };

    assert!(verification_result.is_ok());

    // for metric examples, see https://github.com/facebook/winterfell/blob/main/examples/src/main.rs
    println!(
        "Proof metrics: \n\tSize runtime (bytes): {} \n\tSize serialized (bytes): {} \n\tSecurity level (bits): {} conjectured, {} proven",
        runtime_proof_size_bytes, serilized_proof_size_bytes, conjectured_security_level, proven_security_level
    );
}

#[test]
fn test_run() {
    run();
}

#[allow(dead_code)]
pub fn benchmark(_mimc_rounds: usize, samples: u32) {
    let options = ProofOptions::new(
        NUM_QUERIES,
        BLOWUP_FACTOR,
        GRINDING_FACTOR,
        FIELD_EXTENSION,
        FRI_FOLDING_FACTOR,
        FRI_REMAINDER_MAX_DEGREE,
    );
    let acceptable_options = winterfell::AcceptableOptions::OptionSet(vec![options.clone()]);
    type Hasher = Blake3_256<BaseElement>;

    // Define a source of randomness
    let mut rng: StdRng = SeedableRng::from_seed(RANDOMNESS_SEED);

    // Generate the MiMC round constants
    let mut round_constants = [BaseElement::ZERO; MIMC_ROUNDS];
    for i in 0..round_constants.len() {
        round_constants[i] = BaseElement::new(rng.next_u64() as u128);
    }

    // Generate a random preimage
    let rand_xl: u64 = rng.next_u64();
    let xl = BaseElement::new(rand_xl as u128);
    let rand_xr: u64 = rng.next_u64();
    let xr = BaseElement::new(rand_xr as u128);

    let mut total_proving = Duration::new(0, 0);
    let mut total_verifying = Duration::new(0, 0);
    for _ in 0..samples {
        // Compute the MiMC hash image
        let image = mimc(xl, xr, &round_constants);

        // Create the proof
        let proof = {
            let prover = MiMCProver::<Hasher>::new(options.clone());

            let start = Instant::now();

            let trace = prover.build_trace(xl, xr, &round_constants);
            let proof = prover.prove(trace).unwrap();
            total_proving += start.elapsed();

            proof
        };

        // Verify that the proof is valid
        let verification_result = {
            let pub_inputs = PublicInputs {
                xl,
                xr,
                result: image,
                round_constants,
            };

            let start = Instant::now();

            let verification_result = winterfell::verify::<
                MiMCAir,
                Hasher,
                DefaultRandomCoin<Hasher>,
            >(proof, pub_inputs, &acceptable_options);
            total_verifying += start.elapsed();

            verification_result
        };

        assert!(verification_result.is_ok());
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
    benchmark(MIMC_ROUNDS, SAMPLES);
}

pub struct PublicInputs {
    pub xl: BaseElement,
    pub xr: BaseElement,
    pub result: BaseElement,
    pub round_constants: [BaseElement; MIMC_ROUNDS],
}

impl ToElements<BaseElement> for PublicInputs {
    fn to_elements(&self) -> Vec<BaseElement> {
        let mut result = vec![self.xl, self.xr, self.result];
        result.extend_from_slice(&self.round_constants);
        result
    }
}

pub struct MiMCAir {
    context: AirContext<BaseElement>,
    xl: BaseElement,
    xr: BaseElement,
    result: BaseElement,
}

impl Air for MiMCAir {
    // First, we'll specify which finite field to use for our computation, and also how
    // the public inputs must look like.
    type BaseField = BaseElement;
    type PublicInputs = PublicInputs;

    // Here, we'll construct a new instance of our computation which is defined by 3 parameters:
    // starting value, number of steps, and the end result. Another way to think about it is
    // that an instance of our computation is a specific invocation of the do_work() function.
    fn new(trace_info: TraceInfo, pub_inputs: PublicInputs, options: ProofOptions) -> Self {
        assert_eq!(TRACE_WIDTH, trace_info.width());

        // Our computation requires a single transition constraint. The constraint itself
        // is defined in the evaluate_transition() method below, but here we need to specify
        // the expected degree of the constraint. If the expected and actual degrees of the
        // constraints don't match, an error will be thrown in the debug mode, but in release
        // mode, an invalid proof will be generated which will not be accepted by any verifier.
        let degrees = vec![
            TransitionConstraintDegree::new(3), // first transition is degree 3, since we do two multiplications of 3 equal values (i.e. cube of one value)
            TransitionConstraintDegree::new(1), // second transition is degree 1, since we just compare (no multiplications)
        ];

        // We also need to specify the exact number of assertions we will place against the
        // execution trace. This number must be the same as the number of items in a vector
        // returned from the get_assertions() method below.
        let num_assertions = 3;

        MiMCAir {
            context: AirContext::new(trace_info, degrees, num_assertions, options),
            xl: pub_inputs.xl,
            xr: pub_inputs.xr,
            result: pub_inputs.result,
            // round_constants: pub_inputs.round_constants,
        }
    }

    // In this method we'll define our transition constraints; a computation is considered to
    // be valid, if for all valid state transitions, transition constraints evaluate to all
    // zeros, and for any invalid transition, at least one constraint evaluates to a non-zero
    // value. The `frame` parameter will contain current and next states of the computation.
    fn evaluate_transition<E: FieldElement + From<Self::BaseField>>(
        &self,
        frame: &EvaluationFrame<E>,
        _periodic_values: &[E],
        result: &mut [E],
    ) {
        let current = frame.current();
        let next = frame.next();

        let current_xl = current[0];
        let current_xr = current[1];
        let current_ci = current[2];
        let next_xl = next[0];
        let next_xr = next[1];

        // compute the state that should result from applying the MiMC round
        let current_xlci = current_xl + current_ci;
        let expected_xl = current_xr + current_xlci.cube(); // xl = xr + (xl + ci)^3
        let expected_xr = current_xl;

        // compare the results, ensuring that they are 0 only when they are equal
        result[0] += are_equal(next_xl, expected_xl);
        result[1] += are_equal(next_xr, expected_xr);
    }

    // Here, we'll define a set of assertions about the execution trace which must be satisfied
    // for the computation to be valid. Essentially, this ties computation's execution trace
    // to the public inputs.
    fn get_assertions(&self) -> Vec<Assertion<Self::BaseField>> {
        let last_step = self.trace_length() - 1;
        // Assert starting and ending values of the hash
        let assertions = vec![
            Assertion::single(0, 0, self.xl),
            Assertion::single(1, 0, self.xr),
            Assertion::single(0, last_step, self.result),
        ];

        assertions
    }

    // This is just boilerplate which is used by the Winterfell prover/verifier to retrieve
    // the context of the computation.
    fn context(&self) -> &AirContext<Self::BaseField> {
        &self.context
    }
}

pub struct MiMCProver<H: ElementHasher> {
    options: ProofOptions,
    _hasher: PhantomData<H>,
}

impl<H: ElementHasher> MiMCProver<H> {
    pub fn new(options: ProofOptions) -> Self {
        Self {
            options,
            _hasher: PhantomData,
        }
    }

    pub fn build_trace(
        &self,
        xl: BaseElement,
        xr: BaseElement,
        round_constants: &[BaseElement],
    ) -> TraceTable<BaseElement> {
        let mimc_rounds = MIMC_ROUNDS;
        debug_assert_eq!(mimc_rounds, round_constants.len());
        // NOTE: trace_length must always be a power of 2 and >= 8
        let trace_length = mimc_rounds + 1;
        debug_assert!(trace_length >= 8);
        // allocate memory to hold the trace table
        let mut trace = TraceTable::new(TRACE_WIDTH, trace_length);

        trace.fill(
            |state| {
                let ci = round_constants[0];
                // initialize first state of the computation
                state[0] = xl;
                state[1] = xr;
                state[2] = ci;
            },
            |step, state| {
                // execute the transition function for all steps
                // meaning to apply one round of MiMC hash
                let xl = state[0];
                let xr = state[1];
                let ci = state[2];

                let new_xl = xr + (xl + ci).cube(); // xl = xr + (xl + ci)^3
                let new_xr = xl; // xr = xl
                let new_ci = if step < mimc_rounds - 1 {
                    round_constants[step + 1]
                } else {
                    // The last step sets a round constant that will never be used, and that is not available.
                    BaseElement::ZERO
                };

                state[0] = new_xl;
                state[1] = new_xr;
                state[2] = new_ci;
            },
        );

        trace
    }
}

impl<H: ElementHasher> Prover for MiMCProver<H>
where
    H: ElementHasher<BaseField = BaseElement>,
{
    type BaseField = BaseElement;
    type Air = MiMCAir;
    type Trace = TraceTable<BaseElement>;
    type HashFn = H;
    type RandomCoin = DefaultRandomCoin<Self::HashFn>;
    type TraceLde<E: FieldElement<BaseField = Self::BaseField>> = DefaultTraceLde<E, Self::HashFn>;
    type ConstraintEvaluator<'a, E: FieldElement<BaseField = Self::BaseField>> =
        DefaultConstraintEvaluator<'a, Self::Air, E>;

    fn get_pub_inputs(&self, trace: &Self::Trace) -> PublicInputs {
        let last_step = trace.length() - 1;
        let mut round_constants = [BaseElement::ZERO; MIMC_ROUNDS];
        for i in 0..(trace.length() - 1) {
            round_constants[i] = trace.get(2, i);
        }

        PublicInputs {
            xl: trace.get(0, 0),
            xr: trace.get(1, 0),
            // result image is the xl of the last step.
            result: trace.get(0, last_step),
            round_constants,
        }
    }

    fn options(&self) -> &ProofOptions {
        &self.options
    }

    fn new_trace_lde<E: FieldElement<BaseField = Self::BaseField>>(
        &self,
        trace_info: &TraceInfo,
        main_trace: &ColMatrix<Self::BaseField>,
        domain: &StarkDomain<Self::BaseField>,
    ) -> (Self::TraceLde<E>, TracePolyTable<E>) {
        DefaultTraceLde::new(trace_info, main_trace, domain)
    }

    fn new_evaluator<'a, E: FieldElement<BaseField = Self::BaseField>>(
        &self,
        air: &'a Self::Air,
        aux_rand_elements: AuxTraceRandElements<E>,
        composition_coefficients: ConstraintCompositionCoefficients<E>,
    ) -> Self::ConstraintEvaluator<'a, E> {
        DefaultConstraintEvaluator::new(air, aux_rand_elements, composition_coefficients)
    }
}

// are_equal returns zero only when a == b.
pub fn are_equal<E: FieldElement>(a: E, b: E) -> E {
    a - b
}

// compute_mimc_hash computes a MiMC hash
pub fn mimc(
    xl: BaseElement,
    xr: BaseElement,
    round_constants: &[BaseElement; MIMC_ROUNDS],
) -> BaseElement {
    let mut xl = xl.clone();
    let mut xr = xr.clone();

    for ci in round_constants {
        let next_xl = xr + (xl + *ci).cube(); // xl = xr + (xl + ci)^3
        xr = xl; // xr = xl
        xl = next_xl;
    }

    // result image is the final xl
    xl
}
