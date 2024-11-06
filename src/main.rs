use ark_bn254::Bn254;
use ark_bn254::Fr;
use ark_circom::CircomBuilder;
use ark_circom::CircomConfig;
use ark_groth16::{prepare_verifying_key, Groth16};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_snark::SNARK;
use rand::rngs::StdRng;
use rand::SeedableRng;
use std::path::PathBuf;
use tokio;

#[tokio::main]
async fn main() {
    // Run prover
    let (proof_hex, vk_hex, public_inputs_hex) = run_prover().await;

    // Run verifier
    let verified = run_verifier(&proof_hex, &vk_hex, &public_inputs_hex).await;
    assert!(verified);
}

async fn run_prover() -> (String, String, String) {
    // Load the WASM and R1CS for witness and proof generation
    let wasm_path = PathBuf::from("./circuit/main_js/main.wasm");
    let r1cs_path = PathBuf::from("./circuit/main.r1cs");

    if !wasm_path.exists() {
        panic!("WASM file not found at: {}", wasm_path.display());
    }
    if !r1cs_path.exists() {
        panic!("R1CS file not found at: {}", r1cs_path.display());
    }

    let cfg = CircomConfig::<Fr>::new(wasm_path, r1cs_path).unwrap();
    let mut builder = CircomBuilder::new(cfg);

    // Private inputs: A factorisation of a number
    builder.push_input("a", 3);
    builder.push_input("b", 5);

    let circuit = builder.setup();

    // Generate a random proving key. WARNING: This is not secure. A proving key generated from a ceremony should be used in production.
    let mut rng: StdRng = SeedableRng::from_seed([0; 32]);
    let pk =
        Groth16::<Bn254>::generate_random_parameters_with_reduction(circuit, &mut rng).unwrap();

    let circuit = builder.build().unwrap();
    let public_inputs = circuit.get_public_inputs().unwrap();

    // Create proof
    let proof = Groth16::<Bn254>::prove(&pk, circuit, &mut rng).unwrap();

    // Serialize outputs
    let mut pk_bytes = Vec::new();
    pk.vk.serialize_compressed(&mut pk_bytes).unwrap();
    let vk_hex = hex::encode(pk_bytes);

    let mut proof_serialized = Vec::new();
    proof.serialize_compressed(&mut proof_serialized).unwrap();
    let proof_hex = hex::encode(proof_serialized);

    let mut public_inputs_serialized = Vec::new();
    public_inputs.iter().for_each(|input| {
        input
            .serialize_compressed(&mut public_inputs_serialized)
            .unwrap();
    });
    let public_inputs_hex = hex::encode(public_inputs_serialized);

    (proof_hex, vk_hex, public_inputs_hex)
}

async fn run_verifier(proof_hex: &str, vk_hex: &str, public_inputs_hex: &str) -> bool {
    // Deserialize inputs
    let proof_bytes = hex::decode(proof_hex).unwrap();
    let vk_bytes = hex::decode(vk_hex).unwrap();
    let public_inputs_bytes = hex::decode(public_inputs_hex).unwrap();

    // Prepare verification key
    let vk = ark_groth16::VerifyingKey::<Bn254>::deserialize_compressed(&vk_bytes[..]).unwrap();
    let pvk = prepare_verifying_key(&vk);

    // Deserialize proof
    let proof = ark_groth16::Proof::<Bn254>::deserialize_compressed(&proof_bytes[..]).unwrap();

    // Deserialize public inputs
    let mut public_inputs = Vec::new();
    let mut offset = 0;
    while offset < public_inputs_bytes.len() {
        let input = Fr::deserialize_compressed(&public_inputs_bytes[offset..]).unwrap();
        public_inputs.push(input);
        offset += 32; // Size of compressed Fr
    }

    // Verify proof
    Groth16::<Bn254>::verify_with_processed_vk(&pvk, &public_inputs, &proof).unwrap()
}
