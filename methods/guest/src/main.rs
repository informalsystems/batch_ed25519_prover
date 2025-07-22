use risc0_zkvm::guest::env;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};

fn main() {
    // Decode the verifying key, message, and signature from the inputs.
    let (iterations, encoded_verifying_key, message, signature_bytes): (
        u32,
        [u8; 32],
        Vec<u8>,
        Vec<u8>,
    ) = env::read();
    let verifying_key = VerifyingKey::from_bytes(&encoded_verifying_key).unwrap();
    let signature: Signature = Signature::from_slice(&signature_bytes).unwrap();
    // Verify the signature, panicking if verification fails.
    for _ in 0..iterations {
        verifying_key
            .verify(&message, &signature)
            .expect("Ed25519 signature verification failed");
    }

    // Commit to the journal the verifying key and message that was signed.
    env::commit(&(encoded_verifying_key, message));
}
