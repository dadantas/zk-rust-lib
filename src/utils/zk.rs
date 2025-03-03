
use ark_ec::bn::Bn;
use ark_groth16::{Groth16, PreparedVerifyingKey, Proof, ProvingKey};
use ark_circom::{CircomReduction, WitnessCalculator};
use ark_relations::r1cs::ConstraintMatrices;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_snark::SNARK;
use ark_zkey::{read_arkzkey, SerializableProvingKey, SerializableConstraintMatrices};
use wasmer::Store;
use ark_std::{rand::thread_rng, test_rng};
use ark_bn254::{Bn254, Config, Fr};
use std::{collections::HashMap, fs::File, io::BufReader};
use ark_std::UniformRand;

use color_eyre::eyre::{Result, WrapErr};
use memmap2::Mmap;

pub async fn gen_proof(
    inputs: HashMap<String, Vec<num_bigint::BigInt>>,
    zkey: &(ark_groth16::ProvingKey<Bn254>, ark_relations::r1cs::ConstraintMatrices<Fr>),
    wasm_path: &str
) -> Vec<u8> {
    let (params, matrices) = zkey;

    let num_inputs = matrices.num_instance_variables;
    let num_constraints = matrices.num_constraints;

    let mut store = Store::default();
    let mut wtns = WitnessCalculator::new(
        &mut store,
        &wasm_path
    )
    .unwrap();
    let full_assignment = wtns
        .calculate_witness_element::<Fr, _>(&mut store, inputs, false)
        .unwrap();

    // let mut rng = thread_rng();
    // let rng = &mut rng;
    let rng = &mut test_rng();
    
    let r = ark_bn254::Fr::rand(rng);
    let s = ark_bn254::Fr::rand(rng);

    let proof = Groth16::<Bn254, CircomReduction>::create_proof_with_reduction_and_matrices(
        &params,
        r,
        s,
        &matrices,
        num_inputs,
        num_constraints,
        full_assignment.as_slice(),
    )
    .unwrap();


    let mut proof_bytes = Vec::new();
    proof.serialize_compressed(&mut proof_bytes).unwrap();

    log::info!("Proof generated successfully");
    proof_bytes
}


pub async fn verify_proof(
    pvk: &PreparedVerifyingKey<Bn254>,
    public: &Vec<<ark_ec::models::bn::Bn<ark_bn254::Config> as ark_ec::pairing::Pairing>::ScalarField>,
    proof: &Proof<Bn<Config>>
) -> bool {
    let result = Groth16::<Bn254>::verify_with_processed_vk(pvk, public.as_slice(), proof);
    match result {
        Ok(_) => {
            log::info!("Proof verified successfully");
            result.unwrap()
        }
        Err(_) => {
            log::error!("Proof verification failed");
            false
        }
    }
}


//source from ark-zkey crate, but removed print statements
pub fn read_arkzkey_no_print(arkzkey_path: &str) -> Result<(ProvingKey<Bn254>, ConstraintMatrices<Fr>)> {
    // let now = std::time::Instant::now();
    let arkzkey_file_path = std::path::PathBuf::from(arkzkey_path);
    let arkzkey_file = File::open(arkzkey_file_path).wrap_err("Failed to open arkzkey file")?;
    // println!("Time to open arkzkey file: {:?}", now.elapsed());

    //let mut buf_reader = BufReader::new(arkzkey_file);

    // Using mmap
    // let now = std::time::Instant::now();
    let mmap = unsafe { Mmap::map(&arkzkey_file)? };
    let mut cursor = std::io::Cursor::new(mmap);
    // println!("Time to mmap arkzkey: {:?}", now.elapsed());

    // Was &mut buf_reader
    // let now = std::time::Instant::now();
    let serialized_proving_key =
        SerializableProvingKey::deserialize_compressed_unchecked(&mut cursor)
            .wrap_err("Failed to deserialize proving key")?;
    // println!("Time to deserialize proving key: {:?}", now.elapsed());

    // let now = std::time::Instant::now();
    let serialized_constraint_matrices =
        SerializableConstraintMatrices::deserialize_compressed_unchecked(&mut cursor)
            .wrap_err("Failed to deserialize constraint matrices")?;
    // println!("Time to deserialize matrices: {:?}", now.elapsed());

    let proving_key: ProvingKey<Bn254> = serialized_proving_key.0;
    let constraint_matrices: ConstraintMatrices<Fr> = ConstraintMatrices {
        num_instance_variables: serialized_constraint_matrices.num_instance_variables,
        num_witness_variables: serialized_constraint_matrices.num_witness_variables,
        num_constraints: serialized_constraint_matrices.num_constraints,
        a_num_non_zero: serialized_constraint_matrices.a_num_non_zero,
        b_num_non_zero: serialized_constraint_matrices.b_num_non_zero,
        c_num_non_zero: serialized_constraint_matrices.c_num_non_zero,
        a: serialized_constraint_matrices.a.data,
        b: serialized_constraint_matrices.b.data,
        c: serialized_constraint_matrices.c.data,
    };

    Ok((proving_key, constraint_matrices))
}


pub fn extract_pvk(path: &String, out: &String) {
    let (params, _) = read_arkzkey(path).unwrap();

    let pvk = Groth16::<Bn254>::process_vk(&params.vk).unwrap();


    let mut file = File::create(out).unwrap();
    pvk.serialize_compressed(&mut file).unwrap();

    log::info!("Prepared Verifying Key extracted successfully");
}

pub fn load_pvk(path: &String) -> ark_groth16::PreparedVerifyingKey<Bn254> {
    let file = File::open(path).unwrap();
    let reader = BufReader::new(file);
    let pvk = ark_groth16::PreparedVerifyingKey::<Bn254>::deserialize_compressed_unchecked(reader).unwrap();
    pvk
}
