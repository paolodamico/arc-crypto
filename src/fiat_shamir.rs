use elliptic_curve::hash2curve::FromOkm;
use p256::{ProjectivePoint, Scalar};
use sha2::digest::{ExtendableOutput, Update, XofReader};
use sha3::Shake128;

use crate::types::serialize_element;

/// Non-interactive Schnorr proof challenge generation using SHAKE128.
///
/// Implements the Fiat-Shamir transform for composed sigma protocols over
/// P-256 by hashing the session ID, statement elements, and commitment
/// points through SHAKE128, then reducing to a scalar via `FromOkm`
/// (48-byte XOF output, unbiased mod n per RFC 9380 Section 5.3).
///
/// - Sigma protocols: <https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-sigma-protocols-02>
/// - Fiat-Shamir transform: <https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-fiat-shamir-02>
/// - ARC ciphersuite: <https://ietf-wg-privacypass.github.io/draft-arc/draft-ietf-privacypass-arc-crypto.html#name-arcp-256>
pub struct NISchnorrProofShake128P256 {
    session_id: Vec<u8>,
    statement: Vec<ProjectivePoint>,
}

impl NISchnorrProofShake128P256 {
    #[must_use]
    pub fn new(session_id: Vec<u8>, statement: Vec<ProjectivePoint>) -> Self {
        Self {
            session_id,
            statement,
        }
    }

    /// Consume the prover/verifier state to produce the challenge scalar.
    ///
    /// Feeds `session_id || statement_elements || commitment_points` into
    /// SHAKE128, reads 48 bytes (L=48 per hash-to-field for P-256), and
    /// reduces to a scalar via `FromOkm` (unbiased mod n).
    #[must_use]
    pub fn into_challenge(self, commitment_points: &[ProjectivePoint]) -> Scalar {
        let mut hasher = Shake128::default();
        hasher.update(&self.session_id);

        for e in &self.statement {
            hasher.update(&serialize_element(e));
        }

        for p in commitment_points {
            hasher.update(&serialize_element(p));
        }

        let mut reader = hasher.finalize_xof();
        // FromOkm for P-256 Scalar expects 48 bytes (L=48 per hash_to_field spec, Section 5.3 of RFC 9380).
        #[expect(
            deprecated,
            reason = "FromOkm requires GenericArray from elliptic-curve 0.13"
        )]
        let mut okm =
            elliptic_curve::generic_array::GenericArray::<u8, elliptic_curve::consts::U48>::default(
            );
        reader.read(&mut okm);
        Scalar::from_okm(&okm) // performs modulo reduction
    }
}
