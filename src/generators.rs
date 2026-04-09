use std::sync::LazyLock;

use elliptic_curve::hash2curve::{ExpandMsgXmd, GroupDigest};
use elliptic_curve::sec1::ToEncodedPoint;
use p256::NistP256;
use p256::ProjectivePoint;
use sha2::Sha256;

#[must_use]
pub fn generator_g() -> ProjectivePoint {
    ProjectivePoint::GENERATOR
}

/// Second generator derived via hash-to-curve.
///
/// `H = HashToGroup(SerializeElement(G), "generatorH")`
/// with DST = `"HashToGroup-ARCV1-P256generatorH"`.
///
/// The DST is the expansion of Section 6.1's `HashToGroup` formula:
/// `"HashToGroup-" || contextString || info` where `info = "generatorH"`.
///
/// Reference: <https://ietf-wg-privacypass.github.io/draft-arc/draft-ietf-privacypass-arc-crypto.html#section-3.1>
#[must_use]
pub fn generator_h() -> &'static ProjectivePoint {
    static H: LazyLock<ProjectivePoint> = LazyLock::new(|| {
        let g_compressed = ProjectivePoint::GENERATOR
            .to_affine()
            .to_encoded_point(true);
        let dst = b"HashToGroup-ARCV1-P256generatorH";

        #[expect(clippy::expect_used, reason = "static init with known-valid inputs")]
        NistP256::hash_from_bytes::<ExpandMsgXmd<Sha256>>(
            &[g_compressed.as_bytes()],
            &[dst.as_slice()],
        )
        .expect("hash_from_bytes with valid inputs should not fail")
    });
    &H
}

#[cfg(test)]
mod tests {
    use elliptic_curve::group::GroupEncoding;
    use p256::ProjectivePoint;

    use super::{generator_g, generator_h};

    #[test]
    fn generator_g_is_not_identity() {
        assert_ne!(generator_g(), ProjectivePoint::IDENTITY);
    }

    #[test]
    fn generator_h_is_not_identity() {
        assert_ne!(*generator_h(), ProjectivePoint::IDENTITY);
    }

    #[test]
    fn generator_h_differs_from_g() {
        assert_ne!(generator_g().to_bytes(), generator_h().to_bytes());
    }

    #[test]
    fn generator_h_is_deterministic() {
        let h1 = generator_h();
        let h2 = generator_h();
        assert_eq!(h1.to_bytes(), h2.to_bytes());
    }
}
