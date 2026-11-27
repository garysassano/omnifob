//! `type = "command"` integrations, against shell scripts that stand in for
//! credential helpers. Unix only: the end-to-end tests cover Windows with
//! `fob creds` as the helper.
#![cfg(unix)]

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use crate::support::Scratch;
use jiff::SignedDuration;
use omnifob_core::config::Config;
use omnifob_core::providers;
use omnifob_core::{Endpoints, Profile, Target};

/// A script in `dir` called `name`. Tests run it as `/bin/sh <script>`:
/// executing a file just written fails with ETXTBSY while another test's
/// child, forked meanwhile, still holds it open for writing.
fn script(dir: &Path, name: &str, body: &str) -> PathBuf {
    std::fs::create_dir_all(dir).unwrap();
    let path = dir.join(name);
    std::fs::write(&path, format!("{body}\n")).unwrap();
    path
}

fn helper_config(command: &[&str], extra: &str) -> (Config, Profile) {
    let command = command
        .iter()
        .map(|a| format!("{a:?}"))
        .collect::<Vec<_>>()
        .join(", ");
    let text =
        format!("[integrations.helper]\ntype = \"command\"\ncommand = [{command}]\n{extra}\n");
    let config = Config::parse(&text).unwrap();
    let omnifob_core::Integration::Command(c) = &config.integrations["helper"] else {
        unreachable!()
    };
    let profile = providers::command::discover("helper", c).remove(0);
    (config, profile)
}

fn runs(counter: &Path) -> usize {
    std::fs::read_to_string(counter).map_or(0, |s| s.lines().count())
}

#[tokio::test]
async fn credentials_with_an_expiry_are_cached_and_others_are_not() {
    let scratch = Scratch::new("omnifob-command-cache", Endpoints::default());
    let dir = scratch.state.join("bin");
    let counter = dir.join("runs");
    let expiring = script(
        &dir,
        "expiring",
        &format!(
            "echo run >> '{}'\necho \"helper for $OMNIFOB_PROFILE\" >&2\nprintf '{{\"env\":{{\"TOKEN\":\"%s\"}},\"expires_at\":\"2100-01-01T00:00:00Z\"}}' \"$OMNIFOB_PROFILE\"",
            counter.display()
        ),
    );
    let (config, profile) = helper_config(
        &["/bin/sh", expiring.to_str().unwrap()],
        "name = \"expiring\"",
    );
    assert_eq!(profile.id, "helper/default/expiring");
    assert_eq!(profile.target, Target::Command { aws: false });
    for _ in 0..2 {
        let creds = providers::credentials(&config, &profile, true, None)
            .await
            .unwrap();
        assert_eq!(creds.env["TOKEN"], "helper/default/expiring");
    }
    assert_eq!(runs(&counter), 1);

    let counter = dir.join("runs-forever");
    let forever = script(
        &dir,
        "forever",
        &format!(
            "echo run >> '{}'\necho '{{\"env\":{{\"TOKEN\":\"t\"}}}}'",
            counter.display()
        ),
    );
    let (config, profile) = helper_config(
        &["/bin/sh", forever.to_str().unwrap()],
        "name = \"ci\"\naccount = \"build\"",
    );
    assert_eq!(profile.id, "helper/build/ci");
    for _ in 0..2 {
        providers::credentials(&config, &profile, true, None)
            .await
            .unwrap();
    }
    assert_eq!(runs(&counter), 2, "no expiry: run each time");
}

#[tokio::test]
async fn a_ttl_is_passed_to_the_program_and_capped() {
    let scratch = Scratch::new("omnifob-command-ttl", Endpoints::default());
    let helper = script(
        &scratch.state.join("bin"),
        "ttl",
        "printf '{\"env\":{\"ARG\":\"%s\",\"ENV\":\"%s\"},\"expires_at\":\"2100-01-01T00:00:00Z\"}' \"$1\" \"$OMNIFOB_TTL_SECONDS\"",
    );
    let (config, profile) = helper_config(
        &[
            "/bin/sh",
            helper.to_str().unwrap(),
            "--duration={ttl_seconds}",
        ],
        "ttl = \"1h\"",
    );
    let creds = providers::credentials(&config, &profile, true, None)
        .await
        .unwrap();
    assert_eq!(creds.env["ARG"], "--duration=3600");
    assert_eq!(creds.env["ENV"], "3600");
    let creds =
        providers::credentials(&config, &profile, true, Some(SignedDuration::from_mins(30)))
            .await
            .unwrap();
    assert_eq!(creds.env["ARG"], "--duration=1800");
    // `[agent] max_ttl` caps it, as for the other providers whose lifetime
    // omnifob chooses.
    assert_eq!(
        providers::chosen_lifetime(&config, &profile),
        Some(SignedDuration::from_hours(1))
    );
    assert_eq!(
        providers::capped_ttl(&config, &profile, None, SignedDuration::from_mins(15)),
        Some(SignedDuration::from_mins(15))
    );

    // Without `ttl` the program picks, and `--ttl` is refused.
    let (config, profile) = helper_config(&["/bin/sh", helper.to_str().unwrap()], "");
    assert_eq!(providers::chosen_lifetime(&config, &profile), None);
    let err = providers::credentials(&config, &profile, true, Some(SignedDuration::from_mins(30)))
        .await
        .unwrap_err();
    assert!(err.to_string().contains("set `ttl` on 'helper'"), "{err}");
    let creds = providers::credentials(&config, &profile, false, None)
        .await
        .unwrap();
    assert_eq!(creds.env["ENV"], "", "no lifetime asked for");
}

#[tokio::test]
async fn failures_name_the_program_but_never_its_output() {
    let scratch = Scratch::new("omnifob-command-fail", Endpoints::default());
    let dir = scratch.state.join("bin");
    let error = |command: &[&str], extra: &str| {
        let (config, profile) = helper_config(command, extra);
        async move {
            providers::credentials(&config, &profile, true, None)
                .await
                .unwrap_err()
                .to_string()
        }
    };
    let failing = script(&dir, "failing", "echo 'helper: no sign-in' >&2\nexit 3");
    let e = error(&["/bin/sh", failing.to_str().unwrap()], "").await;
    assert!(
        e.contains("failed (exit status: 3); what it said is above"),
        "{e}"
    );

    let garbage = script(&dir, "garbage", "echo 'AKIA-secret-value'");
    let e = error(&["/bin/sh", garbage.to_str().unwrap()], "").await;
    assert!(e.contains("is not credentials: not JSON"), "{e}");
    assert!(!e.contains("secret-value"), "{e}");

    let expired = script(
        &dir,
        "expired",
        "echo '{\"env\":{\"T\":\"t\"},\"expires_at\":\"2000-01-01T00:00:00Z\"}'",
    );
    let e = error(&["/bin/sh", expired.to_str().unwrap()], "").await;
    assert!(e.contains("printed credentials that expired"), "{e}");

    // A program that prints without end is stopped at 1 MiB, long before
    // its time runs out.
    let endless = script(&dir, "endless", "while :; do echo AKIA-secret-value; done");
    let started = Instant::now();
    let e = error(&["/bin/sh", endless.to_str().unwrap()], "timeout = \"30s\"").await;
    assert!(e.contains("printed more than 1 MiB"), "{e}");
    assert!(!e.contains("secret-value"), "{e}");
    assert!(started.elapsed() < Duration::from_secs(20));

    let missing = dir.join("missing");
    let e = error(&[missing.to_str().unwrap()], "").await;
    assert!(e.contains("was not found"), "{e}");

    let slow = script(&dir, "slow", "sleep 5\necho '{\"env\":{\"T\":\"t\"}}'");
    let started = Instant::now();
    let e = error(&["/bin/sh", slow.to_str().unwrap()], "timeout = \"1s\"").await;
    assert!(
        e.contains("did not finish within 1s; it was stopped"),
        "{e}"
    );
    assert!(started.elapsed() < Duration::from_secs(4));
}

#[tokio::test]
async fn credential_process_output_makes_an_aws_profile() {
    let scratch = Scratch::new("omnifob-command-aws", Endpoints::default());
    let helper = script(
        &scratch.state.join("bin"),
        "aws-helper",
        "echo '{\"Version\":1,\"AccessKeyId\":\"ASIAHELPER\",\"SecretAccessKey\":\"s\",\"SessionToken\":\"t\",\"Expiration\":\"2100-01-01T00:00:00Z\",\"AccountId\":\"123456789012\"}'",
    );
    let (config, profile) = helper_config(
        &["/bin/sh", helper.to_str().unwrap()],
        "format = \"credential-process\"\nregion = \"eu-west-1\"",
    );
    assert_eq!(profile.target, Target::Command { aws: true });
    assert!(profile.target.is_aws());
    let creds = providers::credentials(&config, &profile, true, None)
        .await
        .unwrap();
    assert_eq!(creds.env["AWS_ACCESS_KEY_ID"], "ASIAHELPER");
    assert_eq!(creds.env["AWS_ACCOUNT_ID"], "123456789012");
    assert_eq!(creds.env["AWS_REGION"], "eu-west-1");
    assert_eq!(
        creds.expires_at.unwrap().to_string(),
        "2100-01-01T00:00:00Z"
    );
}
