use elliptic_curve::hash2curve::{ExpandMsgXmd, FromOkm, GroupDigest};
use p256::{NistP256, ProjectivePoint, Scalar};
use sha2::Sha256;
use sha3::Shake128;
use sha3::digest::{ExtendableOutput, Update, XofReader};

use crate::CONTEXT_STRING;
use crate::error::Error;

/// Hash arbitrary data to a P-256 scalar.
///
/// DST = `"HashToScalar-ARCV1-P256"` || `info`
///
/// Reference: <https://ietf-wg-privacypass.github.io/draft-arc/draft-ietf-privacypass-arc-crypto.html#section-6.1>
///
/// # Errors
///
/// Returns `Error::HashToScalar` if the underlying hash-to-field fails.
pub fn hash_to_scalar(data: &[u8], info: &[u8]) -> Result<Scalar, Error> {
    let mut dst = Vec::with_capacity(22 + info.len());
    dst.extend_from_slice(b"HashToScalar-");
    dst.extend_from_slice(CONTEXT_STRING);
    dst.extend_from_slice(info);

    NistP256::hash_to_scalar::<ExpandMsgXmd<Sha256>>(&[data], &[&dst])
        .map_err(|_| Error::HashToScalar)
}

/// Hash arbitrary data to a P-256 curve point.
///
/// DST = `"HashToGroup-ARCV1-P256"` || `info`
///
/// /// Reference: <https://ietf-wg-privacypass.github.io/draft-arc/draft-ietf-privacypass-arc-crypto.html#section-6.1>
///
/// # Errors
///
/// Returns `Error::HashToCurve` if the underlying hash-to-curve fails.
pub fn hash_to_group(data: &[u8], info: &[u8]) -> Result<ProjectivePoint, Error> {
    let mut dst = Vec::with_capacity(21 + info.len());
    dst.extend_from_slice(b"HashToGroup-");
    dst.extend_from_slice(CONTEXT_STRING);
    dst.extend_from_slice(info);

    NistP256::hash_from_bytes::<ExpandMsgXmd<Sha256>>(&[data], &[&dst])
        .map_err(|_| Error::HashToCurve)
}

/// Compute a Fiat-Shamir challenge scalar from a SHAKE128 transcript.
///
/// Feeds `session_id` followed by each serialized element into SHAKE128,
/// reads 48 bytes, and reduces to a scalar via `FromOkm` (unbiased mod n).
#[must_use]
pub fn fiat_shamir_challenge(session_id: &[u8], elements: &[&[u8]]) -> Scalar {
    let mut hasher = Shake128::default();
    hasher.update(session_id);
    for elem in elements {
        hasher.update(elem);
    }
    let mut reader = hasher.finalize_xof();
    // FromOkm for P-256 Scalar expects 48 bytes (L=48 per hash_to_field spec).
    // GenericArray is deprecated but required by the FromOkm trait signature.
    #[expect(
        deprecated,
        reason = "FromOkm requires GenericArray from elliptic-curve 0.13"
    )]
    let mut okm =
        elliptic_curve::generic_array::GenericArray::<u8, elliptic_curve::consts::U48>::default();
    reader.read(&mut okm);
    Scalar::from_okm(&okm)
}

#[cfg(test)]
#[expect(clippy::expect_used, reason = "tests use expect for clarity")]
mod tests {
    use elliptic_curve::Field;
    use p256::ProjectivePoint;

    use super::{fiat_shamir_challenge, hash_to_group, hash_to_scalar};

    #[test]
    fn hash_to_scalar_produces_nonzero() {
        let s = hash_to_scalar(b"test input", b"testInfo").expect("hash_to_scalar should succeed");
        assert!(!bool::from(s.is_zero()));
    }

    #[test]
    fn hash_to_scalar_is_deterministic() {
        let s1 = hash_to_scalar(b"data", b"info").expect("hash_to_scalar should succeed");
        let s2 = hash_to_scalar(b"data", b"info").expect("hash_to_scalar should succeed");
        assert_eq!(s1, s2);
    }

    #[test]
    fn hash_to_scalar_different_info_differs() {
        let s1 = hash_to_scalar(b"data", b"info1").expect("hash_to_scalar should succeed");
        let s2 = hash_to_scalar(b"data", b"info2").expect("hash_to_scalar should succeed");
        assert_ne!(s1, s2);
    }

    #[test]
    fn hash_to_group_produces_valid_point() {
        let p = hash_to_group(b"test input", b"testInfo").expect("hash_to_group should succeed");
        assert_ne!(p, ProjectivePoint::IDENTITY);
    }

    #[test]
    fn fiat_shamir_is_deterministic() {
        let c1 = fiat_shamir_challenge(b"session", &[b"elem1", b"elem2"]);
        let c2 = fiat_shamir_challenge(b"session", &[b"elem1", b"elem2"]);
        assert_eq!(c1, c2);
    }

    #[test]
    fn fiat_shamir_different_input_differs() {
        let c1 = fiat_shamir_challenge(b"session", &[b"elem1"]);
        let c2 = fiat_shamir_challenge(b"session", &[b"elem2"]);
        assert_ne!(c1, c2);
    }
}
