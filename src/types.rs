use elliptic_curve::PrimeField;
use elliptic_curve::group::GroupEncoding;
use elliptic_curve::sec1::FromEncodedPoint;
use p256::{AffinePoint, EncodedPoint, ProjectivePoint, Scalar};

use crate::CONTEXT_STRING;
use crate::error::Error;
use crate::fiat_shamir::NISchnorrProofShake128P256;
use crate::generators::{generator_g, generator_h};

/// Serde helper for `ProjectivePoint` via compressed SEC1 encoding.
///
/// Delegates to `p256::PublicKey`'s serde impl (hex for human-readable,
/// raw bytes for binary formats).
#[cfg(feature = "serde")]
mod point_serde {
    use p256::{ProjectivePoint, PublicKey};
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S: Serializer>(
        point: &ProjectivePoint,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        PublicKey::from_affine(point.to_affine())
            .map_err(serde::ser::Error::custom)?
            .serialize(serializer)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<ProjectivePoint, D::Error> {
        let pk = PublicKey::deserialize(deserializer)?;
        Ok(ProjectivePoint::from(*pk.as_affine()))
    }
}

/// Size of a compressed SEC1 point (P-256).
pub const ELEMENT_SIZE: usize = 33;
/// Size of a serialized scalar (P-256).
pub const SCALAR_SIZE: usize = 32;
/// Size of a serialized `RequestProof`: 1 challenge + 4 responses.
pub const REQUEST_PROOF_SIZE: usize = 5 * SCALAR_SIZE;
/// Size of a serialized `CredentialRequest`: 2 elements + proof.
pub const CREDENTIAL_REQUEST_SIZE: usize = 2 * ELEMENT_SIZE + REQUEST_PROOF_SIZE;
/// Size of a serialized `ResponseProof`: 1 challenge + 7 responses.
pub const RESPONSE_PROOF_SIZE: usize = 8 * SCALAR_SIZE;
/// Size of a serialized `CredentialResponse`: 6 elements + proof.
pub const CREDENTIAL_RESPONSE_SIZE: usize = 6 * ELEMENT_SIZE + RESPONSE_PROOF_SIZE;
/// Size of a serialized `ServerPublicKey`: 3 elements.
pub const SERVER_PUBLIC_KEY_SIZE: usize = 3 * ELEMENT_SIZE;

/// Zero-knowledge proof for a credential request.
///
/// Proves knowledge of `(m1, m2, r1, r2)` satisfying the Pedersen
/// commitment equations without revealing the witnesses.
///
/// Wire format: `challenge[32] || s1[32] || s2[32] || s3[32] || s4[32]`
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct RequestProof {
    pub challenge: Scalar,
    pub responses: [Scalar; 4],
}

impl RequestProof {
    #[must_use]
    pub fn to_bytes(&self) -> [u8; REQUEST_PROOF_SIZE] {
        let mut buf = [0u8; REQUEST_PROOF_SIZE];
        buf[..SCALAR_SIZE].copy_from_slice(&self.challenge.to_repr());
        for (i, response) in self.responses.iter().enumerate() {
            let offset = SCALAR_SIZE + i * SCALAR_SIZE;
            buf[offset..offset + SCALAR_SIZE].copy_from_slice(&response.to_repr());
        }
        buf
    }

    /// # Errors
    ///
    /// Returns an error if any scalar is outside the P-256 field.
    pub fn from_bytes(bytes: &[u8; REQUEST_PROOF_SIZE]) -> Result<Self, Error> {
        let challenge = deserialize_scalar(&bytes[..SCALAR_SIZE])?;
        let mut responses = [Scalar::ZERO; 4];
        for (i, response) in responses.iter_mut().enumerate() {
            let offset = SCALAR_SIZE + i * SCALAR_SIZE;
            *response = deserialize_scalar(&bytes[offset..offset + SCALAR_SIZE])?;
        }
        Ok(Self {
            challenge,
            responses,
        })
    }
}

/// A credential request sent from client to server.
///
/// Contains two Pedersen commitments and a proof of knowledge.
///
/// Wire format: `m1Enc[33] || m2Enc[33] || proof[160]`
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct CredentialRequest {
    #[cfg_attr(feature = "serde", serde(with = "point_serde"))]
    pub m1_enc: ProjectivePoint,
    #[cfg_attr(feature = "serde", serde(with = "point_serde"))]
    pub m2_enc: ProjectivePoint,
    pub proof: RequestProof,
}

impl CredentialRequest {
    #[must_use]
    pub fn to_bytes(&self) -> [u8; CREDENTIAL_REQUEST_SIZE] {
        let mut buf = [0u8; CREDENTIAL_REQUEST_SIZE];
        buf[..ELEMENT_SIZE].copy_from_slice(&serialize_element(&self.m1_enc));
        buf[ELEMENT_SIZE..2 * ELEMENT_SIZE].copy_from_slice(&serialize_element(&self.m2_enc));
        buf[2 * ELEMENT_SIZE..].copy_from_slice(&self.proof.to_bytes());
        buf
    }

    /// # Errors
    ///
    /// Returns an error if point or scalar deserialization fails.
    pub fn from_bytes(bytes: &[u8; CREDENTIAL_REQUEST_SIZE]) -> Result<Self, Error> {
        let m1_enc = deserialize_element(&bytes[..ELEMENT_SIZE])?;
        let m2_enc = deserialize_element(&bytes[ELEMENT_SIZE..2 * ELEMENT_SIZE])?;

        let mut proof_bytes = [0u8; REQUEST_PROOF_SIZE];
        proof_bytes.copy_from_slice(&bytes[2 * ELEMENT_SIZE..]);
        let proof = RequestProof::from_bytes(&proof_bytes)?;

        Ok(Self {
            m1_enc,
            m2_enc,
            proof,
        })
    }
}

/// Deserialize a compressed SEC1-encoded P-256 point.
pub(crate) fn deserialize_element(bytes: &[u8]) -> Result<ProjectivePoint, Error> {
    let encoded = EncodedPoint::from_bytes(bytes).map_err(|_| Error::InvalidPoint)?;
    let affine: Option<AffinePoint> = AffinePoint::from_encoded_point(&encoded).into();
    let Some(affine) = affine else {
        return Err(Error::InvalidPoint);
    };
    Ok(ProjectivePoint::from(affine))
}

/// Deserialize a big-endian scalar, rejecting values outside the field.
pub(crate) fn deserialize_scalar(bytes: &[u8]) -> Result<Scalar, Error> {
    let bytes: &[u8; SCALAR_SIZE] = bytes.try_into().map_err(|_| Error::InvalidScalar)?;
    let field_bytes = p256::FieldBytes::from(*bytes);
    let scalar: Option<Scalar> = Scalar::from_repr(field_bytes).into();
    let Some(scalar) = scalar else {
        return Err(Error::InvalidScalar);
    };
    Ok(scalar)
}

#[must_use]
pub fn serialize_element(point: &ProjectivePoint) -> [u8; ELEMENT_SIZE] {
    let mut buf = [0u8; ELEMENT_SIZE];
    let compressed = point.to_bytes();
    buf.copy_from_slice(compressed.as_ref());
    buf
}

/// Zero-knowledge proof for a credential response.
///
/// Proves the server computed the response correctly using its private key
/// without revealing the key material.
///
/// Wire format: `challenge[32] || s0[32] || ... || s6[32]`
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ResponseProof {
    pub challenge: Scalar,
    pub responses: [Scalar; 7],
}

impl ResponseProof {
    #[must_use]
    pub fn to_bytes(&self) -> [u8; RESPONSE_PROOF_SIZE] {
        let mut buf = [0u8; RESPONSE_PROOF_SIZE];
        buf[..SCALAR_SIZE].copy_from_slice(&self.challenge.to_repr());
        for (i, response) in self.responses.iter().enumerate() {
            let offset = SCALAR_SIZE + i * SCALAR_SIZE;
            buf[offset..offset + SCALAR_SIZE].copy_from_slice(&response.to_repr());
        }
        buf
    }

    /// # Errors
    ///
    /// Returns an error if any scalar is outside the P-256 field.
    pub fn from_bytes(bytes: &[u8; RESPONSE_PROOF_SIZE]) -> Result<Self, Error> {
        let challenge = deserialize_scalar(&bytes[..SCALAR_SIZE])?;
        let mut responses = [Scalar::ZERO; 7];
        for (i, response) in responses.iter_mut().enumerate() {
            let offset = SCALAR_SIZE + i * SCALAR_SIZE;
            *response = deserialize_scalar(&bytes[offset..offset + SCALAR_SIZE])?;
        }
        Ok(Self {
            challenge,
            responses,
        })
    }
}

/// Server's public key for credential issuance.
///
/// Published by the server so clients can verify credential responses.
///
/// Wire format: `X0[33] || X1[33] || X2[33]`
///
/// Reference: <https://ietf-wg-privacypass.github.io/draft-arc/draft-ietf-privacypass-arc-crypto.html#name-key-generation>
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ServerPublicKey {
    #[cfg_attr(feature = "serde", serde(with = "point_serde"))]
    pub x0: ProjectivePoint,
    #[cfg_attr(feature = "serde", serde(with = "point_serde"))]
    pub x1: ProjectivePoint,
    #[cfg_attr(feature = "serde", serde(with = "point_serde"))]
    pub x2: ProjectivePoint,
}

impl ServerPublicKey {
    #[must_use]
    pub fn to_bytes(&self) -> [u8; SERVER_PUBLIC_KEY_SIZE] {
        let mut buf = [0u8; SERVER_PUBLIC_KEY_SIZE];
        buf[..ELEMENT_SIZE].copy_from_slice(&serialize_element(&self.x0));
        buf[ELEMENT_SIZE..2 * ELEMENT_SIZE].copy_from_slice(&serialize_element(&self.x1));
        buf[2 * ELEMENT_SIZE..].copy_from_slice(&serialize_element(&self.x2));
        buf
    }

    /// # Errors
    ///
    /// Returns an error if any point encoding is invalid.
    pub fn from_bytes(bytes: &[u8; SERVER_PUBLIC_KEY_SIZE]) -> Result<Self, Error> {
        let x0 = deserialize_element(&bytes[..ELEMENT_SIZE])?;
        let x1 = deserialize_element(&bytes[ELEMENT_SIZE..2 * ELEMENT_SIZE])?;
        let x2 = deserialize_element(&bytes[2 * ELEMENT_SIZE..])?;
        Ok(Self { x0, x1, x2 })
    }
}

/// A credential response from server to client.
///
/// Contains the blinded MAC elements and a proof of correct issuance.
///
/// Wire format: `U[33] || encUPrime[33] || X0Aux[33] || X1Aux[33] || X2Aux[33] || HAux[33] || proof[256]`
///
/// Reference: <https://ietf-wg-privacypass.github.io/draft-arc/draft-ietf-privacypass-arc-crypto.html#name-credential-response>
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct CredentialResponse {
    #[cfg_attr(feature = "serde", serde(with = "point_serde"))]
    pub u: ProjectivePoint,
    #[cfg_attr(feature = "serde", serde(with = "point_serde"))]
    pub enc_u_prime: ProjectivePoint,
    #[cfg_attr(feature = "serde", serde(with = "point_serde"))]
    pub x0_aux: ProjectivePoint,
    #[cfg_attr(feature = "serde", serde(with = "point_serde"))]
    pub x1_aux: ProjectivePoint,
    #[cfg_attr(feature = "serde", serde(with = "point_serde"))]
    pub x2_aux: ProjectivePoint,
    #[cfg_attr(feature = "serde", serde(with = "point_serde"))]
    pub h_aux: ProjectivePoint,
    pub proof: ResponseProof,
}

impl CredentialResponse {
    #[must_use]
    pub fn to_bytes(&self) -> [u8; CREDENTIAL_RESPONSE_SIZE] {
        let mut buf = [0u8; CREDENTIAL_RESPONSE_SIZE];
        let points = [
            &self.u,
            &self.enc_u_prime,
            &self.x0_aux,
            &self.x1_aux,
            &self.x2_aux,
            &self.h_aux,
        ];
        for (i, point) in points.iter().enumerate() {
            let offset = i * ELEMENT_SIZE;
            buf[offset..offset + ELEMENT_SIZE].copy_from_slice(&serialize_element(point));
        }
        buf[6 * ELEMENT_SIZE..].copy_from_slice(&self.proof.to_bytes());
        buf
    }

    /// # Errors
    ///
    /// Returns an error if any point or scalar encoding is invalid.
    pub fn from_bytes(bytes: &[u8; CREDENTIAL_RESPONSE_SIZE]) -> Result<Self, Error> {
        let u = deserialize_element(&bytes[..ELEMENT_SIZE])?;
        let enc_u_prime = deserialize_element(&bytes[ELEMENT_SIZE..2 * ELEMENT_SIZE])?;
        let x0_aux = deserialize_element(&bytes[2 * ELEMENT_SIZE..3 * ELEMENT_SIZE])?;
        let x1_aux = deserialize_element(&bytes[3 * ELEMENT_SIZE..4 * ELEMENT_SIZE])?;
        let x2_aux = deserialize_element(&bytes[4 * ELEMENT_SIZE..5 * ELEMENT_SIZE])?;
        let h_aux = deserialize_element(&bytes[5 * ELEMENT_SIZE..6 * ELEMENT_SIZE])?;

        let mut proof_bytes = [0u8; RESPONSE_PROOF_SIZE];
        proof_bytes.copy_from_slice(&bytes[6 * ELEMENT_SIZE..]);
        let proof = ResponseProof::from_bytes(&proof_bytes)?;

        Ok(Self {
            u,
            enc_u_prime,
            x0_aux,
            x1_aux,
            x2_aux,
            h_aux,
            proof,
        })
    }
}

impl CredentialRequest {
    /// Verify the credential request's proof of knowledge.
    ///
    /// Reconstructs the prover commitments from the proof and checks
    /// that the Fiat-Shamir challenge matches.
    ///
    /// Reference: <https://ietf-wg-privacypass.github.io/draft-arc/draft-ietf-privacypass-arc-crypto.html#name-credential-request-verify>
    #[must_use]
    pub fn verify_proof(&self) -> bool {
        let g = generator_g();
        let h = *generator_h();
        let [s1, s2, s3, s4] = self.proof.responses;
        let c = self.proof.challenge;

        let r1_commit = g * s1 + h * s3 - self.m1_enc * c;
        let r2_commit = g * s2 + h * s4 - self.m2_enc * c;

        let mut sid = Vec::with_capacity(CONTEXT_STRING.len() + 17);
        sid.extend_from_slice(CONTEXT_STRING);
        sid.extend_from_slice(b"CredentialRequest");

        let statement = vec![g, h, self.m1_enc, self.m2_enc];
        let verifier = NISchnorrProofShake128P256::new(sid, statement);
        let c_prime = verifier.into_challenge(&[r1_commit, r2_commit]);
        c == c_prime
    }
}

impl CredentialResponse {
    /// Verify the credential response proof against the server's public key.
    ///
    /// Reconstructs the prover announcements from the proof responses and
    /// checks that the Fiat-Shamir challenge matches.
    ///
    /// Reference: <https://ietf-wg-privacypass.github.io/draft-arc/draft-ietf-privacypass-arc-crypto.html#name-credential-response-verify>
    #[must_use]
    pub fn verify_proof(
        &self,
        public_key: &ServerPublicKey,
        request: &CredentialRequest,
    ) -> bool {
        let g = generator_g();
        let h = *generator_h();
        let [s0, s1, s2, s3, s4, s5, s6] = self.proof.responses;
        let c = self.proof.challenge;

        // Reconstruct 11 announcements from responses
        let announcements = [
            g * s0 + h * s3 - public_key.x0 * c,
            h * s1 - public_key.x1 * c,
            h * s2 - public_key.x2 * c,
            h * s4 - self.h_aux * c,
            self.h_aux * s3 - self.x0_aux * c,
            h * s5 - self.x1_aux * c,
            public_key.x1 * s4 - self.x1_aux * c,
            public_key.x2 * s4 - self.x2_aux * c,
            h * s6 - self.x2_aux * c,
            g * s4 - self.u * c,
            public_key.x0 * s4 + request.m1_enc * s5
                + request.m2_enc * s6
                - self.enc_u_prime * c,
        ];

        let mut sid = Vec::with_capacity(CONTEXT_STRING.len() + 18);
        sid.extend_from_slice(CONTEXT_STRING);
        sid.extend_from_slice(b"CredentialResponse");

        let statement = vec![
            g,
            h,
            request.m1_enc,
            request.m2_enc,
            self.u,
            self.enc_u_prime,
            public_key.x0,
            public_key.x1,
            public_key.x2,
            self.x0_aux,
            self.x1_aux,
            self.x2_aux,
            self.h_aux,
        ];

        let verifier = NISchnorrProofShake128P256::new(sid, statement);
        let c_prime = verifier.into_challenge(&announcements);
        c == c_prime
    }
}

#[cfg(test)]
#[expect(clippy::expect_used, reason = "tests use expect for clarity")]
mod tests {
    use elliptic_curve::Field;
    use elliptic_curve::group::GroupEncoding;
    use p256::{ProjectivePoint, Scalar};
    use rand_core::OsRng;

    use super::{CREDENTIAL_REQUEST_SIZE, CredentialRequest, REQUEST_PROOF_SIZE, RequestProof};

    #[test]
    fn request_proof_roundtrip() {
        let proof = RequestProof {
            challenge: Scalar::random(&mut OsRng),
            responses: [
                Scalar::random(&mut OsRng),
                Scalar::random(&mut OsRng),
                Scalar::random(&mut OsRng),
                Scalar::random(&mut OsRng),
            ],
        };
        let bytes = proof.to_bytes();
        assert_eq!(bytes.len(), REQUEST_PROOF_SIZE);

        let recovered = RequestProof::from_bytes(&bytes).expect("roundtrip should succeed");
        assert_eq!(proof.challenge, recovered.challenge);
        for (a, b) in proof.responses.iter().zip(recovered.responses.iter()) {
            assert_eq!(a, b);
        }
    }

    #[test]
    fn credential_request_roundtrip() {
        let request = CredentialRequest {
            m1_enc: ProjectivePoint::GENERATOR * Scalar::random(&mut OsRng),
            m2_enc: ProjectivePoint::GENERATOR * Scalar::random(&mut OsRng),
            proof: RequestProof {
                challenge: Scalar::random(&mut OsRng),
                responses: [
                    Scalar::random(&mut OsRng),
                    Scalar::random(&mut OsRng),
                    Scalar::random(&mut OsRng),
                    Scalar::random(&mut OsRng),
                ],
            },
        };
        let bytes = request.to_bytes();
        assert_eq!(bytes.len(), CREDENTIAL_REQUEST_SIZE);

        let recovered = CredentialRequest::from_bytes(&bytes).expect("roundtrip should succeed");
        assert_eq!(request.m1_enc.to_bytes(), recovered.m1_enc.to_bytes());
        assert_eq!(request.m2_enc.to_bytes(), recovered.m2_enc.to_bytes());
        assert_eq!(request.proof.challenge, recovered.proof.challenge);
    }

    #[test]
    fn credential_request_size_is_226() {
        assert_eq!(CREDENTIAL_REQUEST_SIZE, 226);
    }
}

#[cfg(all(test, feature = "serde"))]
#[expect(clippy::expect_used, reason = "tests use expect for clarity")]
mod serde_tests {
    use elliptic_curve::Field;
    use p256::{ProjectivePoint, Scalar};
    use rand_core::OsRng;

    use super::{CredentialRequest, RequestProof};

    fn random_request() -> CredentialRequest {
        CredentialRequest {
            m1_enc: ProjectivePoint::GENERATOR * Scalar::random(&mut OsRng),
            m2_enc: ProjectivePoint::GENERATOR * Scalar::random(&mut OsRng),
            proof: RequestProof {
                challenge: Scalar::random(&mut OsRng),
                responses: [
                    Scalar::random(&mut OsRng),
                    Scalar::random(&mut OsRng),
                    Scalar::random(&mut OsRng),
                    Scalar::random(&mut OsRng),
                ],
            },
        }
    }

    #[test]
    fn credential_request_json_roundtrip() {
        let request = random_request();
        let json = serde_json::to_string(&request).expect("serialize should succeed");
        let recovered: CredentialRequest =
            serde_json::from_str(&json).expect("deserialize should succeed");

        assert_eq!(request.to_bytes(), recovered.to_bytes());
    }

    #[test]
    fn request_proof_json_roundtrip() {
        let proof = RequestProof {
            challenge: Scalar::random(&mut OsRng),
            responses: [
                Scalar::random(&mut OsRng),
                Scalar::random(&mut OsRng),
                Scalar::random(&mut OsRng),
                Scalar::random(&mut OsRng),
            ],
        };
        let json = serde_json::to_string(&proof).expect("serialize should succeed");
        let recovered: RequestProof =
            serde_json::from_str(&json).expect("deserialize should succeed");

        assert_eq!(proof.challenge, recovered.challenge);
        assert_eq!(proof.responses, recovered.responses);
    }
}
