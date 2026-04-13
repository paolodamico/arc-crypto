#![cfg(all(feature = "server", feature = "client", feature = "test-utils"))]
#![expect(clippy::expect_used, reason = "tests use expect for clarity")]

use arc_crypto::{
    server::ServerPrivateKey,
    types::{CredentialRequest, CredentialResponse},
};
use rand_core::OsRng;

#[test]
fn test_end_to_end_flow() {
    let mut rng = OsRng;

    // 4.1 Key Generation (SetupServer)
    let server_sk = ServerPrivateKey::rng(&mut rng);

    // 4.2 Issuance

    // 4.2.1 Credential Request (and client secret generation)
    let (_secrets, request) =
        CredentialRequest::generate(b"my-request-1", &mut rng).expect("generate should succeed");

    // 4.2.2 Credential Response
    let _response = CredentialResponse::from_request(&server_sk, &request, &mut rng)
        .expect("from_request should succeed");

    // TODO: finalize credential
}
