mod hash;

use nizkp_benchmark::hash::mimc::{bulletproof, snark, stark};

fn main() {
    println!("\n------------------------------------------------------------------------\n");

    println!("Running zk-SNARK MiMC hash...");
    snark::run();
    println!("zk-SNARK MiMC hash done!");

    println!("\n------------------------------------------------------------------------\n");

    println!("Running zk-STARK MiMC hash...");
    stark::run();
    println!("zk-STARK MiMC hash done!");

    println!("\n------------------------------------------------------------------------\n");

    println!("Running Bulletproof MiMC hash...");
    bulletproof::run();
    println!("Bulletproof MiMC hash done!");

    println!("\n------------------------------------------------------------------------\n");
}
