//! Test vectors from the ARC reference implementation.
//!
//! Verifies scalar/point intermediate values against the Sage reference
//! vectors at <https://github.com/ietf-wg-privacypass/draft-arc/tree/main/poc/vectors>.
//!
//! Proof bytes are NOT checked because our Fiat-Shamir transform differs
//! from the Sage reference's duplex sponge protocol.

#![cfg(feature = "test-utils")]
#![expect(clippy::expect_used, reason = "test vectors use expect")]

use arc_crypto::{
    client::ClientSecrets,
    generators::{generator_g, generator_h},
    hash::hash_to_scalar,
    server::ServerPrivateKey,
    types::{
        Credential, ServerPublicKey, deserialize_element, deserialize_scalar, serialize_element,
    },
};
use p256::{ProjectivePoint, Scalar};

// Helpers

fn scalar(hex_str: &str) -> Scalar {
    let bytes = hex::decode(hex_str).expect("valid hex");
    deserialize_scalar(&bytes).expect("valid scalar")
}

fn point(hex_str: &str) -> ProjectivePoint {
    let bytes = hex::decode(hex_str).expect("valid hex");
    deserialize_element(&bytes).expect("valid point")
}

fn assert_point_eq(actual: &ProjectivePoint, expected_hex: &str) {
    assert_eq!(hex::encode(serialize_element(actual)), expected_hex,);
}

// Test vectors from <https://ietf-wg-privacypass.github.io/draft-arc/draft-ietf-privacypass-arc-crypto.html#section-10.2>

// ServerKey
const X0: &str = "1008f2c706ae2157c75e41b2d75695c7bf480d0632a1ef447036cafe4cabb021";
const X1: &str = "526e009578f6f25fdec992343f09f5e6c58489c31fcf8a934bbaf85797121bdd";
const X2: &str = "549075ccd3d1c36b3546725c43e71943414409a23b980b2c47a3fc2b9c37679b";
const XB: &str = "7276533ce3c89f04a007c2e8aa7d2e3b36829d0eaab5631347d8336c2da09a8e";
const PK_X0: &str = "03bad54cc48293ef3472ac1ada55c9c9fdb3eb99ee47369bbe1d3ce46b300cd7b3";
const PK_X1: &str = "02a0323862a05707d76862bfa8477eed468441ceae14c8fb1659e0b3020b8a24e1";
const PK_X2: &str = "031d16ef08ede5a347e94a8eca071bec7bedb9d8ba943d24bde912a4e1578e529b";

// CredentialRequest
const M1: &str = "141c4ca5e614af8e5e323eb47a7e7673ebb67caf49dfa8e109f45f231227f7a0";
const M2: &str = "911fb315257d9ae29d47ecb48c6fa27074dee6860a0489f8db6ac9a486be6a3e";
const R1: &str = "5c183d2dea942eb2780afb90cfd94983ae6575d60e350021c8c93008ac503973";
const R2: &str = "044d4a5b5daf00dd1fb4444ca2f8c3facc95d537d5ad0e0a2815c912e98a431d";
const M1_ENC: &str = "033fe5d950712f711e5d292d68f804fad4c35fb7f3f1866516448647d4aab12590";
const M2_ENC: &str = "026502a833ed1d972ee27175e750b1719adee12726c653125887c0d32b1f3747ab";
const REQUEST_CONTEXT: &[u8] = b"test request context";

// CredentialResponse
const B: &str = "9ac9d836ef405f4c6c1de4de18d210c929a8dc786c95e3eac3a828cc19e1636e";
const RESP_U: &str = "021cf52318c97c33472cc8fb42a5b5a774f83c3b36e6c782209d53e5945d99a493";
const ENC_U_PRIME: &str = "02ae23020d5427c7f785a72d77c24997f955e66ab7c378c334b7c259dabdf572d7";
const X0_AUX: &str = "031523abe64e436e65e592abdae322dc556fcbea707757e18d4160ba57d574cd87";
const X1_AUX: &str = "023cc3b53807f6e0082b675794ae9f6b370483ca5a3e6d688c3b81f2fdb6d4ec00";
const X2_AUX: &str = "0329dc7c93f8a231a1f16ec69f0fba446e022ce69945b20f37386a7fda3e573b79";
const H_AUX: &str = "0389746891b6dbf062511619eae7d72ae87630bea1e277a925708fdfef8363a1d4";

// Credential
const CRED_U_PRIME: &str = "02646199272c28911165b4d1c5f4ffbd8a83f686948fd4c7250e28c81dbfecd354";

#[test]
fn server_key_derivation() {
    let g = generator_g();
    let h = *generator_h();

    let x0 = scalar(X0);
    let x1 = scalar(X1);
    let x2 = scalar(X2);
    let xb = scalar(XB);

    assert_point_eq(&(g * x0 + h * xb), PK_X0);
    assert_point_eq(&(h * x1), PK_X1);
    assert_point_eq(&(h * x2), PK_X2);

    // Also verify via the ServerPrivateKey API
    let sk = ServerPrivateKey::from_scalars(x0, x1, x2, xb);
    let pk = sk.as_public_key();
    assert_point_eq(&pk.x0, PK_X0);
    assert_point_eq(&pk.x1, PK_X1);
    assert_point_eq(&pk.x2, PK_X2);
}

#[test]
fn credential_request_values() {
    let g = generator_g();
    let h = *generator_h();

    let m1 = scalar(M1);
    let r1 = scalar(R1);
    let r2 = scalar(R2);

    // m2 is derived from the request context
    let m2 = hash_to_scalar(REQUEST_CONTEXT, b"requestContext").expect("hash_to_scalar");
    assert_eq!(hex::encode(elliptic_curve::PrimeField::to_repr(&m2)), M2,);

    // Pedersen commitments
    assert_point_eq(&(g * m1 + h * r1), M1_ENC);
    assert_point_eq(&(g * m2 + h * r2), M2_ENC);
}

#[test]
fn credential_response_values() {
    let g = generator_g();
    let h = *generator_h();

    let x0 = scalar(X0);
    let x1 = scalar(X1);
    let x2 = scalar(X2);
    let xb = scalar(XB);
    let b = scalar(B);
    let m1_enc = point(M1_ENC);
    let m2_enc = point(M2_ENC);

    let pk_x0 = g * x0 + h * xb;
    let pk_x1 = h * x1;
    let pk_x2 = h * x2;

    // Response elements
    let u = g * b;
    let enc_u_prime = (pk_x0 + m1_enc * x1 + m2_enc * x2) * b;
    let x0_aux = h * (xb * b);
    let x1_aux = pk_x1 * b;
    let x2_aux = pk_x2 * b;
    let h_aux = h * b;

    assert_point_eq(&u, RESP_U);
    assert_point_eq(&enc_u_prime, ENC_U_PRIME);
    assert_point_eq(&x0_aux, X0_AUX);
    assert_point_eq(&x1_aux, X1_AUX);
    assert_point_eq(&x2_aux, X2_AUX);
    assert_point_eq(&h_aux, H_AUX);
}

#[test]
fn credential_finalization() {
    let m1 = scalar(M1);
    let r1 = scalar(R1);
    let r2 = scalar(R2);

    let enc_u_prime = point(ENC_U_PRIME);
    let x0_aux = point(X0_AUX);
    let x1_aux = point(X1_AUX);
    let x2_aux = point(X2_AUX);
    let u = point(RESP_U);
    let pk_x1 = point(PK_X1);

    // U' = encU' - X0Aux - r1*X1Aux - r2*X2Aux
    let u_prime = enc_u_prime - x0_aux - x1_aux * r1 - x2_aux * r2;
    assert_point_eq(&u_prime, CRED_U_PRIME);

    // Verify the Credential matches
    let expected = Credential {
        m1,
        u,
        u_prime,
        x1: pk_x1,
    };
    assert_point_eq(&expected.u_prime, CRED_U_PRIME);
    assert_point_eq(&expected.u, RESP_U);
    assert_point_eq(&expected.x1, PK_X1);
}

/// Full issuance flow using test vector scalars via `from_scalars`.
#[test]
fn full_issuance_from_test_vectors() {
    let sk = ServerPrivateKey::from_scalars(scalar(X0), scalar(X1), scalar(X2), scalar(XB));
    let pk = sk.as_public_key();

    // Verify public key
    assert_eq!(
        pk.to_bytes(),
        ServerPublicKey {
            x0: point(PK_X0),
            x1: point(PK_X1),
            x2: point(PK_X2),
        }
        .to_bytes()
    );

    // Build client secrets from test vectors
    let _secrets = ClientSecrets::from_scalars(scalar(M1), scalar(M2), scalar(R1), scalar(R2));

    // Finalize credential using known response points
    // (we can't call from_request because we can't produce a matching
    // proof, so we construct the CredentialResponse manually)
    let enc_u_prime = point(ENC_U_PRIME);
    let x0_aux = point(X0_AUX);
    let x1_aux = point(X1_AUX);
    let x2_aux = point(X2_AUX);

    // Manual unblinding (same as finalize_credential without proof check)
    let r1 = scalar(R1);
    let r2 = scalar(R2);
    let u_prime = enc_u_prime - x0_aux - x1_aux * r1 - x2_aux * r2;
    assert_point_eq(&u_prime, CRED_U_PRIME);
}
