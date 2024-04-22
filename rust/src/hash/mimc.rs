pub mod bulletproof;
pub mod snark;
pub mod stark;

pub const MIMC_ROUNDS: usize = 255; // must be power of two -1, e.g. 7, 15, 31, etc.
pub const RANDOMNESS_SEED: [u8; 32] = [24u8; 32];
#[allow(dead_code)]
pub const SAMPLES: u32 = 50;

pub fn run() {
    println!("Proving and verifying zk-SNARK...");
    snark::run();
    println!("Finished proving and verifying zk-SNARK!");

    println!("Proving and verifying zk-STARK...");
    stark::run();
    println!("Finished proving and verifying zk-STARK!");

    println!("Proving and verifying Bulletproof...");
    bulletproof::run();
    println!("Finished proving and verifying Bulletproof!");
}
