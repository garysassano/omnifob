//! Live check of the EKS token: STS answers the presigned URL as the
//! cluster's authenticator calls it. Needs AWS credentials in the
//! environment; run with `cargo test --test eks_live -- --ignored`.

#[tokio::test]
#[ignore = "calls AWS STS with the credentials in the environment"]
async fn sts_accepts_the_presigned_get_caller_identity() {
    let mut creds = omnifob_core::Credentials::default();
    for name in [
        "AWS_ACCESS_KEY_ID",
        "AWS_SECRET_ACCESS_KEY",
        "AWS_SESSION_TOKEN",
    ] {
        if let Ok(value) = std::env::var(name) {
            creds.env.insert(name.to_string(), value);
        }
    }
    let region = std::env::var("AWS_REGION").unwrap_or_else(|_| "us-east-1".to_string());
    let (token, _) = omnifob_core::provision::eks_token(&creds, "omnifob-test", &region).unwrap();
    use base64::Engine;
    let url = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(token.strip_prefix("k8s-aws-v1.").unwrap())
        .unwrap();
    let response = reqwest::Client::new()
        .get(String::from_utf8(url).unwrap())
        .header("x-k8s-aws-id", "omnifob-test")
        .header("accept", "application/json")
        .send()
        .await
        .unwrap();
    let status = response.status();
    let body = response.text().await.unwrap();
    assert!(status.is_success(), "{status}: {body}");
    assert!(body.contains("GetCallerIdentityResponse"), "{body}");
}
