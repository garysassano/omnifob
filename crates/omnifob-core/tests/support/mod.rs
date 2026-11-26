//! What the provider test suites share.

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use omnifob_core::context::{ContextBuilder, Entered};
use omnifob_core::store::Keychain;
use omnifob_core::{Context, Endpoints};

/// A test's own context, entered on the test's thread until this is
/// dropped: a scratch state directory, which is then removed even after a
/// failure, an in-memory keychain, and the endpoints of its mock server.
/// Tests on the default single-threaded runtime can therefore run in
/// parallel without sharing anything.
pub struct Scratch {
    pub state: PathBuf,
    pub context: Context,
    _entered: Entered,
}

impl Scratch {
    /// A context whose calls go to `endpoints`.
    #[allow(dead_code)]
    pub fn new(name: &str, endpoints: Endpoints) -> Self {
        Self::with(name, Context::builder().endpoints(endpoints))
    }

    /// The context `builder` describes, with a new scratch state directory
    /// named after `name` and an in-memory keychain.
    pub fn with(name: &str, builder: ContextBuilder) -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let state = std::env::temp_dir().join(format!(
            "{name}-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&state);
        let context = builder.state_dir(&state).keychain(Keychain::Memory).build();
        let entered = context.enter();
        Self {
            state,
            context,
            _entered: entered,
        }
    }

    /// Enters a context like this one, sharing its state directory and
    /// keychain, whose calls go to `endpoints` instead.
    #[allow(dead_code)]
    pub fn switch_endpoints(&self, endpoints: Endpoints) -> Entered {
        let context = Context::builder()
            .state_dir(&self.state)
            .keychain(self.context.shared_keychain().unwrap())
            .endpoints(endpoints)
            .build();
        context.enter()
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.state);
    }
}
