//! Deterministic PRNG for reproducible test vectors.
//!
//! Implements the seeded PRNG from the sigma protocols draft, matching
//! the Sage reference `TestDRNG` class.
//!
//! This MUST NOT be used in production — use a proper CSPRNG instead.
//!
//! Reference: <https://github.com/mmaker/draft-irtf-cfrg-sigma-protocols/blob/main/poc/test_drng.sage>

use std::sync::LazyLock;

use elliptic_curve::PrimeField;
use elliptic_curve::bigint::{Encoding, NonZero, U384};
use elliptic_curve::hash2curve::FromOkm;
use p256::Scalar;
use rand_core::{CryptoRng, RngCore};
use sha3::Shake128;
use sha3::digest::{ExtendableOutput, Update, XofReader};

/// Deterministic PRNG seeded via SHAKE128 for reproducible test vectors.
///
/// Matches the Sage reference `TestDRNG`: the SHAKE128 sponge is
/// initialized with a 168-byte block (personalization zero-padded to
/// SHAKE128 rate), then the 32-byte seed is absorbed.
///
/// Two scalar generation methods are provided to match the Sage
/// reference's two entry points:
/// - [`random_scalar`](Self::random_scalar): `OS2IP(squeeze(48)) % order`
/// - [`random_field_scalar`](Self::random_field_scalar):
///   `OS2IP(squeeze(48)) % (order - 1)` (matches `Scalar.random(rng)`)
///
/// # Warning
///
/// This is for test vector generation only.  Production code MUST use
/// a cryptographically secure RNG (e.g., `OsRng`).
pub struct SeededPrng {
    reader: <Shake128 as ExtendableOutput>::Reader,
}

/// Personalization string for the test PRNG.
const PERSONALIZATION: &[u8] = b"sigma-proofs/TestDRNG/SHAKE128";

/// SHAKE128 rate in bytes (r = 1600 - 2*128 = 1344 bits = 168 bytes).
const SHAKE128_RATE: usize = 168;

/// Seed size in bytes.
pub const SEED_SIZE: usize = 32;

/// P-256 scalar byte length (Ns).
const NS: usize = 32;

/// Squeeze length per scalar: `Ns + 16 = 48` bytes.
const SQUEEZE_LEN: usize = NS + 16;

/// `order - 1` as a 384-bit big-endian value (16 leading zero bytes
/// then the 32-byte representation of `n - 1`).
///
/// P-256 order n = `FFFFFFFF00000000FFFFFFFF...FC632551`
/// n - 1         = `FFFFFFFF00000000FFFFFFFF...FC632550`
static ORDER_MINUS_ONE: LazyLock<NonZero<U384>> = LazyLock::new(|| {
    // P-256 order n - 1, zero-padded to 48 bytes (384 bits) big-endian.
    // n   = FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
    // n-1 = FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632550
    #[rustfmt::skip]
    let bytes: [u8; 48] = [
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xBC, 0xE6, 0xFA, 0xAD, 0xA7, 0x17, 0x9E, 0x84,
        0xF3, 0xB9, 0xCA, 0xC2, 0xFC, 0x63, 0x25, 0x50,
    ];
    // SAFETY: n-1 is nonzero by construction
    NonZero::new(U384::from_be_slice(&bytes)).unwrap()
});

impl SeededPrng {
    /// Create a new seeded PRNG from a 32-byte seed.
    ///
    /// Absorbs a 168-byte initial block (personalization zero-padded
    /// to SHAKE128 rate), then the seed.
    #[must_use]
    pub fn new(seed: &[u8; SEED_SIZE]) -> Self {
        let mut hasher = Shake128::default();

        // Initial block: personalization padded to SHAKE128 rate
        let mut initial_block = [0u8; SHAKE128_RATE];
        initial_block[..PERSONALIZATION.len()]
            .copy_from_slice(PERSONALIZATION);
        hasher.update(&initial_block);
        hasher.update(seed);

        Self {
            reader: hasher.finalize_xof(),
        }
    }

    /// Squeeze `SQUEEZE_LEN` bytes from the XOF.
    fn squeeze(&mut self) -> [u8; SQUEEZE_LEN] {
        let mut buf = [0u8; SQUEEZE_LEN];
        self.reader.read(&mut buf);
        buf
    }

    /// Generate a scalar via `OS2IP(squeeze(48)) % order`.
    ///
    /// Matches the Sage `TestDRNG.random_scalar()`.
    pub fn random_scalar(&mut self) -> Scalar {
        let buf = self.squeeze();
        #[expect(
            deprecated,
            reason = "FromOkm requires GenericArray from elliptic-curve 0.13"
        )]
        let okm = *elliptic_curve::generic_array::GenericArray::<
            u8,
            elliptic_curve::consts::U48,
        >::from_slice(&buf);
        Scalar::from_okm(&okm)
    }

    /// Generate a scalar via `OS2IP(squeeze(48)) % (order - 1)`.
    ///
    /// Matches the Sage `G.ScalarField.random(rng)` which internally
    /// calls `rng.randint(0, order - 1)`.  This is used for protocol
    /// scalars (key generation, client secrets, etc.).
    ///
    /// # Panics
    ///
    /// Never panics in practice: the remainder is always < order.
    pub fn random_field_scalar(&mut self) -> Scalar {
        let buf = self.squeeze();
        let wide = U384::from_be_slice(&buf);
        let (_, rem) = wide.div_rem(&ORDER_MINUS_ONE);
        // rem < order - 1 < order, so it fits in 32 bytes
        let rem_bytes = rem.to_be_bytes(); // 48 bytes
        let mut scalar_bytes = p256::FieldBytes::default();
        scalar_bytes.copy_from_slice(&rem_bytes[16..]);
        // Value is < order, so from_repr always succeeds
        #[expect(clippy::expect_used, reason = "rem < order, always valid")]
        Option::from(Scalar::from_repr(scalar_bytes))
            .expect("remainder < order")
    }
}

impl RngCore for SeededPrng {
    fn next_u32(&mut self) -> u32 {
        let mut buf = [0u8; 4];
        self.reader.read(&mut buf);
        u32::from_le_bytes(buf)
    }

    fn next_u64(&mut self) -> u64 {
        let mut buf = [0u8; 8];
        self.reader.read(&mut buf);
        u64::from_le_bytes(buf)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.reader.read(dest);
    }

    fn try_fill_bytes(
        &mut self,
        dest: &mut [u8],
    ) -> Result<(), rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

impl CryptoRng for SeededPrng {}

#[cfg(test)]
mod tests {
    use elliptic_curve::{Field, PrimeField};

    use super::*;

    #[test]
    fn deterministic_output() {
        let seed = [0x42u8; SEED_SIZE];
        let mut prng1 = SeededPrng::new(&seed);
        let mut prng2 = SeededPrng::new(&seed);

        let s1 = prng1.random_scalar();
        let s2 = prng2.random_scalar();
        assert_eq!(s1, s2);
    }

    #[test]
    fn successive_scalars_differ() {
        let seed = [0x01u8; SEED_SIZE];
        let mut prng = SeededPrng::new(&seed);

        let s1 = prng.random_scalar();
        let s2 = prng.random_scalar();
        assert_ne!(s1, s2);
    }

    #[test]
    fn different_seeds_differ() {
        let mut prng1 = SeededPrng::new(&[0xAAu8; SEED_SIZE]);
        let mut prng2 = SeededPrng::new(&[0xBBu8; SEED_SIZE]);

        let s1 = prng1.random_scalar();
        let s2 = prng2.random_scalar();
        assert_ne!(s1, s2);
    }

    #[test]
    fn output_is_nonzero() {
        let mut prng = SeededPrng::new(&[0x00u8; SEED_SIZE]);
        for _ in 0..10 {
            let s = prng.random_scalar();
            assert!(!bool::from(s.is_zero()));
        }
    }

    /// Verify the first scalar against the ARC test vectors.
    ///
    /// `Scalar.random(rng)` → `rng.randint(0, order-1)` → `% (order-1)`
    #[test]
    fn matches_arc_test_vector_x0() {
        let mut seed = [0u8; SEED_SIZE];
        seed[..16].copy_from_slice(b"test vector seed");
        let mut prng = SeededPrng::new(&seed);

        let x0 = prng.random_field_scalar();
        assert_eq!(
            hex::encode(x0.to_repr()),
            "1008f2c706ae2157c75e41b2d75695c7\
             bf480d0632a1ef447036cafe4cabb021",
        );
    }
}
