//! What the provider test suites share.

use std::path::PathBuf;

use tokio::sync::MutexGuard;

/// A test's hold on its suite's lock plus its scratch state directory, which
/// is removed when this is dropped, even after a failure, before the next
/// test may run.
pub struct Scratch {
    pub state: PathBuf,
    _guard: MutexGuard<'static, ()>,
}

impl Scratch {
    /// Points `XDG_STATE_HOME` at a new scratch directory named after `name`
    /// and this process.
    pub fn new(guard: MutexGuard<'static, ()>, name: &str) -> Self {
        let state = std::env::temp_dir().join(format!("{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&state);
        // SAFETY: the tests run one at a time under their suite's lock, held
        // in `guard`, and nothing else in this process reads the environment
        // concurrently.
        unsafe {
            std::env::set_var("XDG_STATE_HOME", &state);
        }
        Self {
            state,
            _guard: guard,
        }
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.state);
    }
}
