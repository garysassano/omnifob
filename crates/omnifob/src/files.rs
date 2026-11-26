//! Files fob writes outside its state directory: the omnifob config and the
//! AWS config. They are replaced with
//! [`omnifob_core::files::write_atomically`], which keeps a file's
//! permissions and symbolic links.

use anyhow::Context;

pub(crate) use omnifob_core::files::write_atomically;

pub(crate) fn aws_config_file(
    file: Option<std::path::PathBuf>,
) -> anyhow::Result<std::path::PathBuf> {
    file.or_else(|| std::env::var_os("AWS_CONFIG_FILE").map(Into::into))
        .or_else(|| std::env::home_dir().map(|h| h.join(".aws/config")))
        .context("cannot find the AWS config file; pass --file")
}
