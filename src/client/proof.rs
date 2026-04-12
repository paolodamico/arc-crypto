use p256::{ProjectivePoint, Scalar};

use crate::CONTEXT_STRING;
use crate::generators::{generator_g, generator_h};
use crate::hash::fiat_shamir_challenge;
use crate::types::serialize_element;

/// Session ID for credential request proofs.
pub(super) fn session_id() -> Vec<u8> {
    let mut sid = Vec::with_capacity(CONTEXT_STRING.len() + 17);
    sid.extend_from_slice(CONTEXT_STRING);
    sid.extend_from_slice(b"CredentialRequest");
    sid
}

/// Build the Fiat-Shamir transcript and compute the challenge scalar.
pub(super) fn compute_challenge(
    m1_enc: &ProjectivePoint,
    m2_enc: &ProjectivePoint,
    r1_commit: &ProjectivePoint,
    r2_commit: &ProjectivePoint,
) -> Scalar {
    let sid = session_id();
    let g_bytes = serialize_element(&generator_g());
    let h_bytes = serialize_element(generator_h());
    let m1_bytes = serialize_element(m1_enc);
    let m2_bytes = serialize_element(m2_enc);
    let r1_bytes = serialize_element(r1_commit);
    let r2_bytes = serialize_element(r2_commit);

    fiat_shamir_challenge(
        &sid,
        &[
            &g_bytes, &h_bytes, &m1_bytes, &m2_bytes, &r1_bytes, &r2_bytes,
        ],
    )
}
