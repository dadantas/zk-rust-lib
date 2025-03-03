use ark_bn254::{Bn254, Fr};
use ark_serialize::CanonicalDeserialize;
use once_cell::sync::Lazy;
use std::collections::HashMap;
use std::fs::File;
use utils::zk::{load_pvk, read_arkzkey_no_print};

use ark_relations::r1cs::ConstraintMatrices;
use std::ffi::{CStr, CString};
use std::sync::Mutex;

mod utils;

use utils::string_utils::str_to_bigint;

#[repr(C)]
pub struct ProofResult {
    pub proof_ptr: *mut u8,
    pub proof_len: u64,
}

// Global variable to store the zkey it's expensive to read it
static ZKEY_DATA: Lazy<Mutex<Option<(ark_groth16::ProvingKey<Bn254>, ConstraintMatrices<Fr>)>>> =
    Lazy::new(|| Mutex::new(None));

#[no_mangle]
// should be used a single time to read the zkey
pub extern "C" fn read_zkey(path: *const std::os::raw::c_char) -> i32 {
    let c_str = unsafe { CStr::from_ptr(path) };
    let path_str = c_str.to_str().unwrap_or("setup/keys/aes_test.arkzkey"); // default path
    let mut file = File::open(path_str).unwrap();
    let (params, matrices) = ark_circom::read_zkey(&mut file).unwrap();
    let mut data = ZKEY_DATA.lock().unwrap();
    *data = Some((params, matrices));
    0
}

#[no_mangle]
pub extern "C" fn gen_proof(
    inputs: *const std::os::raw::c_char,
    wasm_path: *const std::os::raw::c_char,
) -> *mut ProofResult {
    let proof = tokio::runtime::Runtime::new().unwrap().block_on(async {
        let c_str = unsafe { CStr::from_ptr(inputs) };
        let inputs_str = c_str.to_str().unwrap_or("{}");
        let inputs: HashMap<String, Vec<num_bigint::BigInt>> = {
            let raw_inputs: HashMap<String, Vec<String>> = serde_json::from_str(inputs_str).unwrap();
            raw_inputs.into_iter().map(|(k, v)| (k, v.into_iter().map(|x| str_to_bigint(&x).unwrap()).collect())).collect()
        };

        let wasm_c_str = unsafe { CStr::from_ptr(wasm_path) };
        let wasm_path_str = wasm_c_str.to_str().unwrap_or("wasm/aes.wasm");
        let data = ZKEY_DATA.lock().unwrap();
        let zkey = data.as_ref().unwrap();
        utils::zk::gen_proof(inputs, zkey, wasm_path_str).await
    });

    let proof_bytes = proof.clone();
    let proof_ptr = proof_bytes.as_ptr() as *mut u8;

    std::mem::forget(proof_bytes); // Prevent deallocation
    let proof_len = proof.len() as u64;

    let result = Box::new(ProofResult { proof_ptr, proof_len });
    Box::into_raw(result)
}



#[no_mangle]
pub extern "C" fn verify_proof(
    raw_proof_length: i64,
    raw_proof: *const i8,
    pvk_path: *const std::os::raw::c_char,
    raw_public: *const std::os::raw::c_char,
) -> bool {
    let c_str = unsafe { CStr::from_ptr(raw_public) };
    let public_str = c_str.to_str().unwrap_or("[]");
    let public: Vec<
        <ark_ec::models::bn::Bn<ark_bn254::Config> as ark_ec::pairing::Pairing>::ScalarField,
    > = {
        let raw_public: Vec<String> = serde_json::from_str(public_str).unwrap();
        raw_public
            .into_iter()
            .map(|x| utils::string_utils::str_to_fr(&x).unwrap())
            .collect()
    };

    let c_str = unsafe { CStr::from_ptr(pvk_path) };
    let pvk_path_str = c_str.to_str().unwrap();
    let pvk = load_pvk(&pvk_path_str.to_string());

    let proof_length = raw_proof_length as usize;
    let proof_slice = unsafe { std::slice::from_raw_parts(raw_proof as *const u8, proof_length) };
    let mut proof_cursor = std::io::Cursor::new(proof_slice);
    let proof = ark_groth16::Proof::<Bn254>::deserialize_compressed(&mut proof_cursor).unwrap();


    tokio::runtime::Runtime::new()
        .unwrap()
        .block_on(async { utils::zk::verify_proof(&pvk, &public, &proof).await })
}


//MEMORY MANAGEMENT
#[no_mangle]
pub extern "C" fn free_proof(proof: *mut ProofResult) {
    if !proof.is_null() {
        unsafe {
            let boxed_proof = Box::from_raw(proof);
            if !boxed_proof.proof_ptr.is_null() {
                let _ = Vec::from_raw_parts(boxed_proof.proof_ptr, boxed_proof.proof_len as usize, boxed_proof.proof_len as usize);
            }
        }
    }
}


#[no_mangle]
pub extern "C" fn free_string(s: *mut std::os::raw::c_char) {
    if s.is_null() {
        return;
    }
    unsafe {
        let _ = CString::from_raw(s);
    }
}