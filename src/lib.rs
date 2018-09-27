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
// use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
// use std::time::Instant;

#[no_mangle]
pub extern fn singleparty_create_proof_helper(n: usize, value: u64) -> Vec<u8>{
    let m: usize = 1;

    use bincode;
    let max_bitsize = 64;
    let max_parties = 1;

    let pc_gens = PedersenGens::default();
    let bp_gens = BulletproofGens::new(max_bitsize, max_parties);

    // Serialized proof data
    let proof_bytes: Vec<u8>;
    // let value_commitments: Vec<RistrettoPoint>;

    // Prover's scope
    {
        // 1. Generate the proof
        let mut transcript = Transcript::new(b"test");

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

        // // XXX would be nice to have some convenience API for this
        // value_commitments = values
        //     .iter()
        //     .zip(blindings.iter())
        //     .map(|(&v, &v_blinding)| pc_gens.commit(v.into(), v_blinding))
        //     .collect();
    }
    proof_bytes
}

#[cfg(target_os="android")]
#[allow(non_snake_case)]
pub mod android {
    extern crate libc;
    extern crate jni;

    use self::libc::{c_void, size_t};
    use std::os::raw::{c_char};
    use std::ffi::{CString, CStr};
    use self::jni::objects::{JClass, JString};
    use self::jni::sys::{jbyteArray, jboolean, jint};
    use self::jni::JNIEnv;
    use singleparty_create_proof_helper;

    #[no_mangle]
    pub unsafe extern fn Java_com_example_louis_clientcreateproof_CreateProof_proofsize(jre: JNIEnv, _: JClass, n: size_t, value: JString) -> jbyteArray {
        let c_str_value = unsafe { CStr::from_ptr(jre.get_string(value).expect("invalid pattern string").as_ptr())};
        let rust_value = match c_str_value.to_str() {
            Err(_) => "Cannot get valid input",
            Ok(string) => string,
        };
        let u64_value = rust_value.parse::<u64>().unwrap();
        let outcome:Vec<u8> = singleparty_create_proof_helper(n, u64_value);
        jre.byte_array_from_slice(&outcome).unwrap()
    }
}