use ed25519_dalek::SigningKey;
use rand::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GeneratedKeypair {
    pub secret: [u8; 64],
    pub pubkey: [u8; 32],
}

pub struct GeneratedCandidate {
    seed: [u8; 32],
    pub pubkey: [u8; 32],
}

pub struct KeyGenerator {
    rng: ChaCha20Rng,
}

impl KeyGenerator {
    #[inline(always)]
    pub fn new() -> Self {
        Self {
            rng: ChaCha20Rng::from_entropy(),
        }
    }

    #[inline(always)]
    pub fn generate_keypair(&mut self) -> GeneratedKeypair {
        generate_keypair(&mut self.rng)
    }

    #[inline(always)]
    pub fn generate_candidate(&mut self) -> GeneratedCandidate {
        generate_candidate(&mut self.rng)
    }
}

#[inline(always)]
pub fn generate_keypair(rng: &mut ChaCha20Rng) -> GeneratedKeypair {
    generate_candidate(rng).into_keypair()
}

#[inline(always)]
pub fn generate_candidate(rng: &mut ChaCha20Rng) -> GeneratedCandidate {
    let mut seed = [0u8; 32];
    rng.fill_bytes(&mut seed);
    let signing_key = SigningKey::from_bytes(&seed);
    let pubkey = signing_key.verifying_key().to_bytes();

    GeneratedCandidate { seed, pubkey }
}

impl GeneratedCandidate {
    #[cold]
    #[inline(never)]
    pub fn into_keypair(self) -> GeneratedKeypair {
        let mut secret = [0u8; 64];
        secret[..32].copy_from_slice(&self.seed);
        secret[32..].copy_from_slice(&self.pubkey);

        GeneratedKeypair {
            secret,
            pubkey: self.pubkey,
        }
    }
}
