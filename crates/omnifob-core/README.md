# omnifob-core

The library behind [omnifob](https://github.com/garysassano/omnifob)'s `fob` command: integrations (identity sources you sign in to once, such as AWS IAM Identity Center, Google Cloud, Microsoft Entra ID or Cloudflare), the profiles they discover, and the short-lived credentials each profile produces.

Everything that talks to a provider or to the keychain lives here; the command line only presents it. What the library works with (files, keychain, HTTP client, MFA prompt, endpoint overrides) comes from a `Context`, so an embedder can point it at its own state directory, an in-memory keychain or mock endpoints.

```rust
use omnifob_core::store::Keychain;
use omnifob_core::{Config, Context};

fn main() -> anyhow::Result<()> {
    let context = Context::builder().keychain(Keychain::Memory).build();
    let _entered = context.enter();
    let config = Config::parse("[integrations.gh]\ntype = \"token\"\npreset = \"github\"\n")?;
    println!("{} integration(s)", config.integrations.len());
    Ok(())
}
```

The API follows omnifob's version and may change between `0.x` releases. See the [repository](https://github.com/garysassano/omnifob) for configuration, providers and design notes, and [docs.rs](https://docs.rs/omnifob-core) for the API.

Licensed under the MIT licence.
