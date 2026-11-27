//! The agent skill in `skills/omnifob`, as installed copies of it: people
//! install it with their agent's skill tooling (`npx skills add
//! garysassano/omnifob`), and a copy older than fob teaches the agent
//! commands and messages that have changed. Its front matter names the fob
//! release it describes (`metadata.fob-version`), so fob can tell.

use std::path::PathBuf;

/// The fob release this binary is, which a current skill names.
pub(crate) const VERSION: &str = env!("CARGO_PKG_VERSION");

/// An installed copy of the skill.
pub(crate) struct Copy {
    pub(crate) path: PathBuf,
    /// The release it describes; `None` for copies from before the field.
    pub(crate) version: Option<String>,
}

impl Copy {
    pub(crate) fn is_current(&self) -> bool {
        self.version.as_deref() == Some(VERSION)
    }

    /// What is wrong with an out-of-date copy, and what fixes it.
    pub(crate) fn problem(&self) -> Option<String> {
        if self.is_current() {
            return None;
        }
        let path = self.path.display();
        Some(match self.version.as_deref() {
            Some(v) if newer(v, VERSION) => format!(
                "the omnifob skill in {path} describes fob {v}, newer than this fob {VERSION}; upgrade fob"
            ),
            Some(v) => format!(
                "the omnifob skill in {path} describes fob {v}, not {VERSION}; update it (`npx skills update`)"
            ),
            None => format!(
                "the omnifob skill in {path} describes an older fob than {VERSION}; update it (`npx skills update`)"
            ),
        })
    }
}

/// The copies of the skill in the folders agents read global skills from,
/// each once even when several folders link to it.
pub(crate) fn installed() -> Vec<Copy> {
    let mut seen = Vec::new();
    let mut copies = Vec::new();
    for dir in skill_dirs() {
        let path = dir.join("omnifob").join("SKILL.md");
        let Ok(text) = std::fs::read_to_string(&path) else {
            continue;
        };
        let real = std::fs::canonicalize(&path).unwrap_or_else(|_| path.clone());
        if seen.contains(&real) {
            continue;
        }
        seen.push(real);
        copies.push(Copy {
            path,
            version: version_in(&text),
        });
    }
    copies
}

/// The global skill folders of the agents that document one: the shared
/// `~/.agents/skills` (Codex, OpenCode and `npx skills`), Claude Code's,
/// Codex's own and OpenCode's.
fn skill_dirs() -> Vec<PathBuf> {
    let var = |name: &str| {
        std::env::var_os(name)
            .filter(|v| !v.is_empty())
            .map(PathBuf::from)
    };
    let Some(home) = std::env::home_dir() else {
        return Vec::new();
    };
    let config = var("XDG_CONFIG_HOME").unwrap_or_else(|| home.join(".config"));
    let mut dirs = vec![home.join(".agents").join("skills")];
    dirs.push(
        var("CLAUDE_CONFIG_DIR")
            .unwrap_or_else(|| home.join(".claude"))
            .join("skills"),
    );
    dirs.push(
        var("CODEX_HOME")
            .unwrap_or_else(|| home.join(".codex"))
            .join("skills"),
    );
    dirs.push(config.join("opencode").join("skills"));
    dirs
}

/// `metadata.fob-version` in a skill's front matter.
fn version_in(text: &str) -> Option<String> {
    let text = text.replace("\r\n", "\n");
    let front = text.strip_prefix("---\n")?;
    let front = &front[..front.find("\n---")?];
    front.lines().find_map(|line| {
        let value = line.trim().strip_prefix("fob-version:")?.trim();
        let value = value.trim_matches(|c| c == '"' || c == '\'');
        (!value.is_empty()).then(|| value.to_string())
    })
}

/// Whether version `a` is a later release than `b`; versions that do not
/// parse are not.
fn newer(a: &str, b: &str) -> bool {
    fn parse(v: &str) -> Option<Vec<u64>> {
        v.split('.').map(|p| p.parse().ok()).collect()
    }
    matches!((parse(a), parse(b)), (Some(a), Some(b)) if a > b)
}

/// The skill shipped in this repository, for the test that keeps its
/// version in step with the crate's.
#[cfg(test)]
fn repository_skill() -> PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../skills/omnifob/SKILL.md")
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::*;

    /// Release step 1 bumps the skill's `fob-version` with the crate.
    #[test]
    fn the_skill_names_this_release() {
        let text = std::fs::read_to_string(repository_skill()).unwrap();
        assert_eq!(
            version_in(&text).as_deref(),
            Some(VERSION),
            "set metadata.fob-version in skills/omnifob/SKILL.md to {VERSION}"
        );
    }

    #[test]
    fn versions_are_read_from_the_front_matter_only() {
        let skill = "---\nname: omnifob\nmetadata:\n  fob-version: \"1.2.3\"\n---\n\nbody\n";
        assert_eq!(version_in(skill).as_deref(), Some("1.2.3"));
        assert_eq!(
            version_in(&skill.replace('\n', "\r\n")).as_deref(),
            Some("1.2.3")
        );
        assert_eq!(
            version_in("---\nname: omnifob\n---\nfob-version: 9.9.9\n"),
            None
        );
        assert_eq!(version_in("no front matter"), None);
    }

    #[test]
    fn copies_say_what_fixes_them() {
        let copy = |version: Option<&str>| Copy {
            path: Path::new("/skills/omnifob/SKILL.md").to_path_buf(),
            version: version.map(str::to_string),
        };
        assert!(copy(Some(VERSION)).problem().is_none());
        let old = copy(Some("0.0.1")).problem().unwrap();
        assert!(old.contains("npx skills update"), "{old}");
        let new = copy(Some("999.0.0")).problem().unwrap();
        assert!(new.contains("upgrade fob"), "{new}");
        assert!(copy(None).problem().unwrap().contains("older fob"));
        assert!(newer("0.10.0", "0.9.9"));
        assert!(!newer("0.9.9", "0.10.0"));
        assert!(!newer("x", "0.1.0"));
    }
}
