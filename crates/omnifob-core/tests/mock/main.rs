//! The provider suites, each against a mock of its provider's APIs. One
//! test binary rather than one per suite: each binary links the whole
//! library and its dependencies again, which costs minutes and gigabytes.

mod support;

mod aws_iam;
mod aws_login;
mod aws_sso;
mod azure;
mod cloudflare_mint;
mod cloudflare_oauth;
mod command;
mod gcp;
mod token;
