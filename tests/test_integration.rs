#![cfg(feature = "test-utils")]
#![expect(clippy::expect_used, reason = "tests use expect for clarity")]

use arc_crypto::{
    server::ServerPrivateKey,
    types::{CredentialRequest, CredentialResponse},
};
use rand_core::OsRng;

#[test]
fn end_to_end_issuance() {
    let mut rng = OsRng;

    // 4.1 Key Generation
    let server_sk = ServerPrivateKey::rng(&mut rng);
    let server_pk = server_sk.as_public_key();

    // 4.2.1 Credential Request
    let (secrets, request) =
        CredentialRequest::generate(b"my-request-1", &mut rng).expect("generate should succeed");

    // 4.2.2 Credential Response
    let response = CredentialResponse::from_request(&server_sk, &request, &mut rng)
        .expect("from_request should succeed");

    // 4.2.3 Credential Finalization
    let credential = secrets
        .finalize_credential(&response, &server_pk, &request)
        .expect("finalize should succeed");

    assert_eq!(credential.u, response.u);
    assert_eq!(credential.x1, server_pk.x1);
}
