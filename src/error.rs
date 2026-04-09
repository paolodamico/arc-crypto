/// Errors that can occur during ARC protocol operations.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("hash to curve failed")]
    HashToCurve,

    #[error("hash to scalar failed")]
    HashToScalar,

    #[error("invalid curve point encoding")]
    InvalidPoint,

    #[error("invalid scalar encoding")]
    InvalidScalar,

    #[error("proof verification failed")]
    ProofVerification,
}
