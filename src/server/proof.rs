use elliptic_curve::Field;
use p256::{ProjectivePoint, Scalar};
use rand_core::CryptoRngCore;

use crate::CONTEXT_STRING;
use crate::fiat_shamir::NISchnorrProofShake128P256;
use crate::generators::{generator_g, generator_h};
use crate::types::{CredentialRequest, ResponseProof, ServerPublicKey};

use super::ServerPrivateKey;

impl ResponseProof {
    /// Generate the proof of correct credential response issuance.
    ///
    /// Proves knowledge of `(x0, x1, x2, x0_blinding, b, t1, t2)`
    /// satisfying 11 algebraic relations linking the server's private
    /// key, the blinding factor, and the response elements.
    ///
    /// `witnesses`: `[b, t1, t2]` where `t1 = b * x1`, `t2 = b * x2`.
    ///
    /// `response_points`: `[U, encUPrime, X0Aux, X1Aux, X2Aux, HAux]`
    ///
    /// Reference: <https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-sigma-protocols-02#section-6.2>
    #[expect(
        clippy::many_single_char_names,
        reason = "cryptographic variables follow spec naming (g, h, b, k, c)"
    )]
    pub(super) fn from_issuance(
        private_key: &ServerPrivateKey,
        public_key: &ServerPublicKey,
        request: &CredentialRequest,
        witnesses: [Scalar; 3],
        response_points: &[ProjectivePoint; 6],
        rng: &mut impl CryptoRngCore,
    ) -> Self {
        let g = generator_g();
        let h = *generator_h();
        let [b, t1, t2] = witnesses;
        let h_aux = response_points[5];

        // 7 nonces for (x0, x1, x2, x0_blinding, b, t1, t2)
        let k: [Scalar; 7] = std::array::from_fn(|_| Scalar::random(&mut *rng));

        // 11 commitments (one per equation, in spec order)
        let commitments = [
            g * k[0] + h * k[3],  // X0 = x0*G + x0Blinding*H
            h * k[1],             // X1 = x1*H
            h * k[2],             // X2 = x2*H
            h * k[4],             // HAux = b*H
            h_aux * k[3],         // X0Aux = x0Blinding*HAux
            h * k[5],             // X1Aux = t1*H
            public_key.x1 * k[4], // X1Aux = b*X1
            public_key.x2 * k[4], // X2Aux = b*X2
            h * k[6],             // X2Aux = t2*H
            g * k[4],             // U = b*G
            public_key.x0 * k[4]    // encUPrime = b*X0
                + request.m1_enc * k[5]  //   + t1*m1Enc
                + request.m2_enc * k[6], //   + t2*m2Enc
        ];

        let mut sid = Vec::with_capacity(CONTEXT_STRING.len() + 18);
        sid.extend_from_slice(CONTEXT_STRING);
        sid.extend_from_slice(b"CredentialResponse");

        let statement = vec![
            g,
            h,
            request.m1_enc,
            request.m2_enc,
            response_points[0], // U
            response_points[1], // encUPrime
            public_key.x0,
            public_key.x1,
            public_key.x2,
            response_points[2], // X0Aux
            response_points[3], // X1Aux
            response_points[4], // X2Aux
            response_points[5], // HAux
        ];

        let prover = NISchnorrProofShake128P256::new(sid, statement);
        let c = prover.into_challenge(&commitments);

        let secret_witnesses = [
            private_key.x0,
            private_key.x1,
            private_key.x2,
            private_key.x0_blinding,
            b,
            t1,
            t2,
        ];

        let responses: [Scalar; 7] = std::array::from_fn(|i| k[i] + c * secret_witnesses[i]);

        Self {
            challenge: c,
            responses,
        }
    }
}
