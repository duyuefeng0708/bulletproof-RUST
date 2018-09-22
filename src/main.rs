#![cfg_attr(feature = "bench", feature(test))]
#![feature(nll)]
#![feature(test)]
#![feature(external_doc)]
#![doc(include = "../README.md")]
#![doc(html_logo_url = "https://doc.dalek.rs/assets/dalek-logo-clear.png")]

//! Note that docs will only build on nightly Rust until
//! [RFC 1990 stabilizes](https://github.com/rust-lang/rust/issues/44732).

extern crate byteorder;
extern crate core;
extern crate curve25519_dalek;
extern crate digest;
extern crate bincode;

#[macro_use]
extern crate failure;
extern crate merlin;
extern crate rand;
extern crate sha3;
extern crate subtle;
extern crate tiny_keccak;

#[macro_use]
extern crate serde_derive;
extern crate serde;

#[cfg(test)]
extern crate test;

mod util;

#[doc(include = "../docs/notes.md")]
mod notes {}
mod errors;
mod generators;
mod inner_product_proof;
mod range_proof;
mod transcript;

pub use merlin::Transcript;

pub use errors::ProofError;
pub use generators::{BulletproofGens, BulletproofGensShare, PedersenGens};
pub use range_proof::RangeProof;

#[doc(include = "../docs/aggregation-api.md")]
pub mod aggregation {
    pub use errors::MPCError;
    pub use range_proof::dealer;
    pub use range_proof::messages;
    pub use range_proof::party;
}

// use rand::rngs::OsRng;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use std::time::Instant;

fn singleparty_create_and_verify_helper(n: usize, value: u64) {
    // Split the test into two scopes, so that it's explicit what
    // data is shared between the prover and the verifier.

    // Use bincode for serialization
    let mut now = Instant::now();
    use bincode;
    let m = 1usize;

    // Both prover and verifier have access to the generators and the proof
    let max_bitsize = 64;
    let max_parties = 8;
    let pc_gens = PedersenGens::default();
    let bp_gens = BulletproofGens::new(max_bitsize, max_parties);

    // Serialized proof data
    let proof_bytes: Vec<u8>;
    let value_commitments: Vec<RistrettoPoint>;

    // Prover's scope
    {
        // 1. Generate the proof
        let mut transcript = Transcript::new(b"AggregatedRangeProofTest");

        // use rand::Rng;
        let mut rng = rand::thread_rng();

        // let (min, max) = (0u64, ((1u128 << n) - 1) as u64);
        // let values: Vec<u64> = (0..m).map(|_| rng.gen_range(min, max)).collect();
        let values: Vec<u64> = (0..m).map(|_| value).collect();
        let blindings: Vec<Scalar> = (0..m).map(|_| Scalar::random(&mut rng)).collect();

        let proof = RangeProof::prove_multiple(
            &bp_gens,
            &pc_gens,
            &mut transcript,
            &values,
            &blindings,
            n,
        ).unwrap();

        // 2. Serialize
        proof_bytes = bincode::serialize(&proof).unwrap();

        // XXX would be nice to have some convenience API for this
        value_commitments = values
            .iter()
            .zip(blindings.iter())
            .map(|(&v, &v_blinding)| pc_gens.commit(v.into(), v_blinding))
            .collect();
    }

    let mut elapsed = now.elapsed();
    let mut ms = (elapsed.as_secs() as f64) + (elapsed.subsec_nanos() as f64 / 1000_000_000.0) * 1000.0;
    println!("Proof generation time for n={} bits is {:.2} ms", n, ms);

    println!(
        "Bulletproof of n={} bits has size {} bytes",
        n,
        proof_bytes.len(),
    );

    now = Instant::now();
    // Verifier's scope
    {
        // 3. Deserialize
        let proof: RangeProof = bincode::deserialize(&proof_bytes).unwrap();

        // 4. Verify with the same customization label as above
        let mut transcript = Transcript::new(b"AggregatedRangeProofTest");

        assert!(
            proof
                .verify(&bp_gens, &pc_gens, &mut transcript, &value_commitments, n)
                .is_ok()
        );
    }
    elapsed = now.elapsed();
    ms = (elapsed.as_secs() as f64) + (elapsed.subsec_nanos() as f64 / 1000_000_000.0) * 1000.0;
    println!("Proof verification time for n={} bits is {:.2} ms", n, ms);
}

fn main(){
    use std::env;

    let args: Vec<String> = env::args().collect();

    let bit = &args[1];
    let value = &args[2];
    singleparty_create_and_verify_helper(bit.parse::<usize>().unwrap(), value.parse::<u64>().unwrap());
}