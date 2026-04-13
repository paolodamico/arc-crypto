use elliptic_curve::Field;
use p256::{ProjectivePoint, Scalar};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::CONTEXT_STRING;
use crate::error::Error;
use crate::fiat_shamir::NISchnorrProofShake128P256;
use crate::generators::{generator_g, generator_h};
use crate::hash::hash_to_scalar;
use crate::types::{CredentialRequest, RequestProof};

/// Client secrets generated during credential request creation.
///
/// These must be retained in memory by the client to finalize the credential
/// after receiving the server's response.
// FIXME: Secrecy
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct ClientSecrets {
    m1: Scalar,
    m2: Scalar,
    r1: Scalar,
    r2: Scalar,
}

impl ClientSecrets {
    /// Creates a set of client secrets for a `CredentialRequest`.
    ///
    /// Reference: <https://ietf-wg-privacypass.github.io/draft-arc/draft-ietf-privacypass-arc-crypto.html#section-4.2.1>
    ///
    /// # Errors
    /// Will error if the request unexpectedly cannot be hashed into the scalar field
    pub fn from_request_context<R: rand_core::CryptoRng + rand_core::RngCore>(
        rng: &mut R,
        context: &[u8],
    ) -> Result<Self, Error> {
        Ok(Self {
            m1: Scalar::random(&mut *rng),
            m2: hash_to_scalar(context, b"requestContext")?,
            r1: Scalar::random(&mut *rng),
            r2: Scalar::random(&mut *rng),
        })
    }
}

impl CredentialRequest {
    /// Generate a credential request for the given request context.
    ///
    /// Produces Pedersen commitments and a Schnorr proof of knowledge
    /// of `(m1, m2, r1, r2)` satisfying:
    /// - `m1_enc = m1 * G + r1 * H`
    /// - `m2_enc = m2 * G + r2 * H`
    ///
    /// Returns the client's secrets (needed to finalize the credential later)
    /// and the credential request to send to the server.
    ///
    /// # Errors
    ///
    /// Returns `Error::HashToScalar` if deriving `m2` from the request context
    /// fails.
    pub fn generate<R: rand_core::CryptoRng + rand_core::RngCore>(
        request_context: &[u8],
        rng: &mut R,
    ) -> Result<(ClientSecrets, Self), Error> {
        let g = generator_g();
        let h = *generator_h();

        let secrets = ClientSecrets::from_request_context(&mut *rng, request_context)?;

        // Encrypt m1 and m2 secrets
        let m1_enc = g * secrets.m1 + h * secrets.r1;
        let m2_enc = g * secrets.m2 + h * secrets.r2;

        let proof = RequestProof::from_request_commitments(&secrets, &m1_enc, &m2_enc, rng);

        Ok((
            secrets,
            Self {
                m1_enc,
                m2_enc,
                proof,
            },
        ))
    }
}

impl RequestProof {
    /// Equivalent to `MakeCredentialRequestProof`
    ///
    /// Compute the Fiat-Shamir challenge for a credential request proof.
    ///
    /// Transcript: `session_id || G || H || m1Enc || m2Enc || A1 || A2`
    fn from_request_commitments<R: rand_core::CryptoRng + rand_core::RngCore>(
        secrets: &ClientSecrets,
        m1_enc: &ProjectivePoint,
        m2_enc: &ProjectivePoint,
        rng: &mut R,
    ) -> Self {
        let g = generator_g();
        let h = *generator_h();

        // Random masks
        let k1 = Scalar::random(&mut *rng); // m1_var
        let k2 = Scalar::random(&mut *rng); // m2_var
        let k3 = Scalar::random(&mut *rng); // r1_var
        let k4 = Scalar::random(&mut *rng); // r2_var

        // Schnorr internal commitments
        let r1_commit = g * k1 + h * k3;
        let r2_commit = g * k2 + h * k4;

        let mut sid = Vec::with_capacity(CONTEXT_STRING.len() + 17);
        sid.extend_from_slice(CONTEXT_STRING);
        sid.extend_from_slice(b"CredentialRequest");

        let statement = vec![g, h, *m1_enc, *m2_enc];

        let prover = NISchnorrProofShake128P256::new(sid, statement);
        let c = prover.into_challenge(&[r1_commit, r2_commit]);

        Self {
            challenge: c,
            responses: [
                k1 + c * secrets.m1,
                k2 + c * secrets.m2,
                k3 + c * secrets.r1,
                k4 + c * secrets.r2,
            ],
        }
    }
}

#[cfg(test)]
#[expect(clippy::expect_used, reason = "tests")]
mod tests {
    use elliptic_curve::Field;
    use p256::{ProjectivePoint, Scalar};
    use rand_core::OsRng;

    use crate::types::{CREDENTIAL_REQUEST_SIZE, CredentialRequest};

    #[test]
    fn generate_succeeds() {
        let (secrets, request) = CredentialRequest::generate(b"test-context", &mut OsRng)
            .expect("generate should succeed");

        assert_ne!(secrets.m1, secrets.m2);

        let bytes = request.to_bytes();
        assert_eq!(bytes.len(), CREDENTIAL_REQUEST_SIZE);
    }

    #[test]
    fn generated_proof_verifies() {
        let (_secrets, request) = CredentialRequest::generate(b"some-context", &mut OsRng)
            .expect("generate should succeed");

        assert!(request.verify_proof());
    }

    #[test]
    fn generated_request_roundtrips() {
        let (_secrets, request) = CredentialRequest::generate(b"roundtrip-ctx", &mut OsRng)
            .expect("generate should succeed");

        let bytes = request.to_bytes();
        let recovered = CredentialRequest::from_bytes(&bytes).expect("from_bytes should succeed");

        assert!(recovered.verify_proof());
    }

    #[test]
    fn proof_rejects_wrong_commitment() {
        let (_secrets, mut request) = CredentialRequest::generate(b"test-context", &mut OsRng)
            .expect("generate should succeed");

        request.m1_enc = request.m1_enc.add(&ProjectivePoint::GENERATOR);
        assert!(!request.verify_proof());
    }

    #[test]
    fn proof_rejects_wrong_challenge() {
        let (_secrets, mut request) = CredentialRequest::generate(b"test-context", &mut OsRng)
            .expect("generate should succeed");

        request.proof.challenge = Scalar::random(&mut OsRng);
        assert!(!request.verify_proof());
    }

    #[test]
    fn proof_rejects_wrong_response() {
        let (_secrets, mut request) = CredentialRequest::generate(b"test-context", &mut OsRng)
            .expect("generate should succeed");

        request.proof.responses[0] = Scalar::random(&mut OsRng);
        assert!(!request.verify_proof());
    }
}
