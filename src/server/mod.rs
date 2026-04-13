mod proof;

use elliptic_curve::Field;
use p256::Scalar;
use rand_core::CryptoRngCore;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::Error;
use crate::generators::{generator_g, generator_h};
use crate::types::{CredentialRequest, CredentialResponse, ServerPublicKey};

/// Server's private key for credential issuance.
///
/// Contains four scalars used to compute MACs on client attributes.
///
/// Reference: <https://ietf-wg-privacypass.github.io/draft-arc/draft-ietf-privacypass-arc-crypto.html#name-key-generation>
// FIXME: Zeroize
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct ServerPrivateKey {
    pub x0: Scalar,
    x1: Scalar,
    x2: Scalar,
    x0_blinding: Scalar,
}

impl ServerPrivateKey {
    /// Generate a random server keypair.
    ///
    /// # Errors
    ///
    /// This function is infallible but returns the keypair as a tuple
    /// for ergonomic use: `let (sk, pk) = ServerPrivateKey::generate(&mut rng);`
    pub fn rng<R: rand_core::CryptoRng + rand_core::RngCore>(rng: &mut R) -> Self {
        let x0 = Scalar::random(&mut *rng);
        let x1 = Scalar::random(&mut *rng);
        let x2 = Scalar::random(&mut *rng);
        let x0_blinding = Scalar::random(&mut *rng);

        Self {
            x0,
            x1,
            x2,
            x0_blinding,
        }
    }

    /// Derive the corresponding public key.
    #[must_use]
    pub fn as_public_key(&self) -> ServerPublicKey {
        let g = generator_g();
        let h = *generator_h();
        ServerPublicKey {
            x0: g * self.x0 + h * self.x0_blinding,
            x1: h * self.x1,
            x2: h * self.x2,
        }
    }
}

impl CredentialResponse {
    /// Create a credential response for the given request.
    ///
    /// Verifies the request proof from the client, computes the blinded MAC, and
    /// generates a proof of correct issuance.
    ///
    /// Reference: <https://ietf-wg-privacypass.github.io/draft-arc/draft-ietf-privacypass-arc-crypto.html#name-credential-response>
    ///
    /// # Errors
    ///
    /// Returns [`Error::ProofVerification`] if the request's proof is
    /// invalid.
    pub fn from_request(
        private_key: &ServerPrivateKey,
        request: &CredentialRequest,
        rng: &mut impl CryptoRngCore,
    ) -> Result<Self, Error> {
        if !request.verify_proof() {
            return Err(Error::ProofVerification);
        }

        let g = generator_g();
        let h = *generator_h();
        let b = Scalar::random(&mut *rng);

        let public_key = private_key.as_public_key();

        let u = g * b;
        let enc_u_prime =
            (public_key.x0 + request.m1_enc * private_key.x1 + request.m2_enc * private_key.x2) * b;
        let x0_aux = h * (private_key.x0_blinding * b);
        let x1_aux = public_key.x1 * b;
        let x2_aux = public_key.x2 * b;
        let h_aux = h * b;

        let t1 = b * private_key.x1;
        let t2 = b * private_key.x2;

        let response_points = [u, enc_u_prime, x0_aux, x1_aux, x2_aux, h_aux];
        let response_proof = proof::make_response_proof(
            private_key,
            &public_key,
            request,
            [b, t1, t2],
            &response_points,
            rng,
        );

        Ok(Self {
            u,
            enc_u_prime,
            x0_aux,
            x1_aux,
            x2_aux,
            h_aux,
            proof: response_proof,
        })
    }
}

#[cfg(all(test, feature = "client"))]
#[expect(clippy::expect_used, reason = "tests use expect for clarity")]
mod tests {
    use elliptic_curve::Field;
    use p256::Scalar;
    use rand_core::OsRng;

    use crate::types::{
        CREDENTIAL_RESPONSE_SIZE, CredentialRequest, CredentialResponse, SERVER_PUBLIC_KEY_SIZE,
        ServerPublicKey,
    };

    use super::ServerPrivateKey;

    #[test]
    fn keygen_produces_consistent_keys() {
        let sk = ServerPrivateKey::rng(&mut OsRng);
        let pk1 = sk.as_public_key();
        let pk2 = sk.as_public_key();
        assert_eq!(pk1.to_bytes(), pk2.to_bytes());
    }

    #[test]
    fn public_key_roundtrip() {
        let sk = ServerPrivateKey::rng(&mut OsRng);
        let pk = sk.as_public_key();
        let bytes = pk.to_bytes();
        assert_eq!(bytes.len(), SERVER_PUBLIC_KEY_SIZE);
        let recovered = ServerPublicKey::from_bytes(&bytes).expect("from_bytes should succeed");
        assert_eq!(pk.to_bytes(), recovered.to_bytes());
    }

    #[test]
    fn create_response_succeeds() {
        let sk = ServerPrivateKey::rng(&mut OsRng);
        let pk = sk.as_public_key();
        let (_secrets, request) = CredentialRequest::generate(b"test-context", &mut OsRng)
            .expect("generate should succeed");

        let response = CredentialResponse::from_request(&sk, &request, &mut OsRng)
            .expect("from_request should succeed");

        assert!(response.verify_proof(&pk, &request));
    }

    #[test]
    fn response_roundtrip() {
        let sk = ServerPrivateKey::rng(&mut OsRng);
        let pk = sk.as_public_key();
        let (_secrets, request) =
            CredentialRequest::generate(b"roundtrip", &mut OsRng).expect("generate should succeed");

        let response = CredentialResponse::from_request(&sk, &request, &mut OsRng)
            .expect("from_request should succeed");

        let bytes = response.to_bytes();
        assert_eq!(bytes.len(), CREDENTIAL_RESPONSE_SIZE);

        let recovered = CredentialResponse::from_bytes(&bytes).expect("from_bytes should succeed");
        assert!(recovered.verify_proof(&pk, &request));
    }

    #[test]
    fn rejects_invalid_request_proof() {
        let sk = ServerPrivateKey::rng(&mut OsRng);
        let (_secrets, mut request) =
            CredentialRequest::generate(b"bad-proof", &mut OsRng).expect("generate should succeed");

        request.proof.responses[0] = Scalar::random(&mut OsRng);

        let result = CredentialResponse::from_request(&sk, &request, &mut OsRng);
        assert!(result.is_err());
    }

    #[test]
    fn response_proof_rejects_wrong_public_key() {
        let sk = ServerPrivateKey::rng(&mut OsRng);
        let (_secrets, request) =
            CredentialRequest::generate(b"wrong-pk", &mut OsRng).expect("generate should succeed");

        let response = CredentialResponse::from_request(&sk, &request, &mut OsRng)
            .expect("from_request should succeed");

        let other_sk = ServerPrivateKey::rng(&mut OsRng);
        let other_pk = other_sk.as_public_key();
        assert!(!response.verify_proof(&other_pk, &request));
    }

    #[test]
    fn response_proof_rejects_wrong_request() {
        let sk = ServerPrivateKey::rng(&mut OsRng);
        let pk = sk.as_public_key();
        let (_secrets, request) =
            CredentialRequest::generate(b"context-1", &mut OsRng).expect("generate should succeed");

        let response = CredentialResponse::from_request(&sk, &request, &mut OsRng)
            .expect("from_request should succeed");

        let (_secrets2, other_request) =
            CredentialRequest::generate(b"context-2", &mut OsRng).expect("generate should succeed");
        assert!(!response.verify_proof(&pk, &other_request));
    }

    #[test]
    fn response_size_is_454() {
        assert_eq!(CREDENTIAL_RESPONSE_SIZE, 454);
    }

    #[test]
    fn public_key_size_is_99() {
        assert_eq!(SERVER_PUBLIC_KEY_SIZE, 99);
    }
}
