//! `[browsers]`: the browsers integrations open in, and console isolation.

use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use anyhow::Context;
use serde::Deserialize;

use crate::Profile;

/// A browser, or one profile of a browser, that integrations open their
/// sign-ins and consoles in, so that each integration's sessions stay where
/// they belong.
#[derive(Debug, Clone, Deserialize)]
#[cfg_attr(test, derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct Browser {
    /// Which browser this is. fob finds the browsers it knows where they are
    /// installed and knows how to open them; `command` runs any other
    /// program.
    #[serde(rename = "type")]
    pub kind: BrowserType,
    /// Where the browser is, when fob does not find it on its own: an
    /// absolute path (a macOS `.app` bundle or the program inside it), one
    /// under `~/`, or a program name on `PATH`. Not for `command`.
    #[serde(default)]
    pub path: Option<String>,
    /// The browser's own profile that sign-ins and other providers' consoles
    /// open in: a Chromium profile folder, as `chrome://version` shows it
    /// (`Default`, `Profile 1`), or a Firefox profile name. Not for
    /// `command`.
    #[serde(default)]
    pub profile: Option<String>,
    /// With `type = "command"`: the program and its arguments, run without a
    /// shell; `{url}` in an argument is replaced by the URL, e.g.
    /// `["flatpak", "run", "org.mozilla.firefox", "{url}"]`.
    #[serde(default)]
    pub command: Vec<String>,
    /// With `type = "command"`: the engine the program's browser is built
    /// on, which decides how its consoles can be kept apart. Without it,
    /// they are not.
    #[serde(default)]
    pub engine: Option<Engine>,
    /// How each AWS profile's console is kept apart from the others, so that
    /// signing in as one does not sign the console out of another. Defaults
    /// to what the browser supports: `profile` for Chromium-based browsers,
    /// `container` for Firefox-based ones, `none` for the rest.
    #[serde(default)]
    pub isolate: Option<Isolation>,
    /// The colour and icon of the Firefox containers of the profiles each
    /// entry matches, the first match winning (`isolate = "container"`).
    /// Unmatched containers get the add-on's own.
    #[serde(default)]
    pub containers: Vec<ContainerStyle>,
}

/// The browsers fob knows, and `command` for any other.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[cfg_attr(test, derive(schemars::JsonSchema))]
#[serde(rename_all = "kebab-case")]
pub enum BrowserType {
    /// Google Chrome (Chromium).
    Chrome,
    /// Microsoft Edge (Chromium).
    Edge,
    /// Brave (Chromium).
    Brave,
    /// Vivaldi (Chromium).
    Vivaldi,
    /// Chromium, and ungoogled-chromium.
    Chromium,
    /// Helium (Chromium).
    Helium,
    /// Thorium (Chromium).
    Thorium,
    /// Opera (Chromium); its consoles are not kept apart.
    Opera,
    /// Arc (Chromium); its consoles are not kept apart.
    Arc,
    /// Firefox, with its Developer Edition, Nightly and ESR (Gecko).
    Firefox,
    /// Zen (Gecko).
    Zen,
    /// LibreWolf (Gecko).
    Librewolf,
    /// Waterfox (Gecko).
    Waterfox,
    /// Floorp (Gecko).
    Floorp,
    /// Safari (WebKit, macOS); its consoles are not kept apart.
    Safari,
    /// Orion (WebKit, macOS); its consoles are not kept apart.
    Orion,
    /// Any other program, given as `command`.
    Command,
}

/// The browser engine a browser is built on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[cfg_attr(test, derive(schemars::JsonSchema))]
#[serde(rename_all = "lowercase")]
pub enum Engine {
    /// Chromium (Blink): profiles, chosen with `--profile-directory`.
    Chromium,
    /// Mozilla's Gecko: Container Tabs, through the Granted Containers
    /// add-on.
    Gecko,
    /// Apple's WebKit: nothing a command line can choose.
    Webkit,
}

/// How a browser keeps AWS consoles apart, one per fob profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[cfg_attr(test, derive(schemars::JsonSchema))]
#[serde(rename_all = "kebab-case")]
pub enum Isolation {
    /// A browser profile per fob profile (`--profile-directory`), which the
    /// browser creates on first use. Chromium-based browsers.
    Profile,
    /// A container (Firefox's Container Tabs) per fob profile, opened
    /// through the Granted Containers add-on's `ext+granted-containers:`
    /// URLs. Firefox-based browsers with the add-on.
    Container,
    /// Every console in the browser profile sign-ins open in, so signing in
    /// as one AWS profile signs the console out of another.
    #[serde(rename = "none")]
    Off,
}

/// How a browser is told which of its profiles to open.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProfileSwitch {
    /// `--profile-directory=<folder>`, Chromium's.
    Directory,
    /// `-P <name>`, Firefox's.
    Named,
}

/// A folder Windows installs programs in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WindowsRoot {
    /// `%ProgramFiles%`
    ProgramFiles,
    /// `%ProgramFiles(x86)%`
    ProgramFilesX86,
    /// `%LOCALAPPDATA%`, where per-user installs go.
    LocalAppData,
}

use WindowsRoot::{LocalAppData, ProgramFiles, ProgramFilesX86};

/// Where a browser is installed, as its installers and packages put it.
struct Install {
    /// Paths below the Windows folders, in the order they are tried.
    windows: &'static [(WindowsRoot, &'static str)],
    /// App bundles in `/Applications` or `~/Applications`, and the program
    /// inside `Contents/MacOS`.
    macos: &'static [(&'static str, &'static str)],
    /// Program names on `PATH` on Linux, Flatpak app ids included (Flatpak
    /// puts them in its `exports/bin`).
    linux: &'static [&'static str],
}

impl BrowserType {
    /// The browser's name as its maker writes it.
    pub fn name(self) -> &'static str {
        match self {
            Self::Chrome => "Google Chrome",
            Self::Edge => "Microsoft Edge",
            Self::Brave => "Brave",
            Self::Vivaldi => "Vivaldi",
            Self::Chromium => "Chromium",
            Self::Helium => "Helium",
            Self::Thorium => "Thorium",
            Self::Opera => "Opera",
            Self::Arc => "Arc",
            Self::Firefox => "Firefox",
            Self::Zen => "Zen",
            Self::Librewolf => "LibreWolf",
            Self::Waterfox => "Waterfox",
            Self::Floorp => "Floorp",
            Self::Safari => "Safari",
            Self::Orion => "Orion",
            Self::Command => "command",
        }
    }

    /// The engine the browser is built on; `None` for `command`, whose
    /// engine the config says.
    pub fn engine(self) -> Option<Engine> {
        match self {
            Self::Chrome
            | Self::Edge
            | Self::Brave
            | Self::Vivaldi
            | Self::Chromium
            | Self::Helium
            | Self::Thorium
            | Self::Opera
            | Self::Arc => Some(Engine::Chromium),
            Self::Firefox | Self::Zen | Self::Librewolf | Self::Waterfox | Self::Floorp => {
                Some(Engine::Gecko)
            }
            Self::Safari | Self::Orion => Some(Engine::Webkit),
            Self::Command => None,
        }
    }

    /// How the browser's command line picks one of its profiles. Opera and
    /// Arc are built on Chromium but keep profiles their own way, and
    /// WebKit browsers take no such switch.
    fn profile_switch(self) -> Option<ProfileSwitch> {
        match self {
            Self::Opera | Self::Arc | Self::Safari | Self::Orion | Self::Command => None,
            _ => match self.engine() {
                Some(Engine::Chromium) => Some(ProfileSwitch::Directory),
                Some(Engine::Gecko) => Some(ProfileSwitch::Named),
                _ => None,
            },
        }
    }

    /// The kinds of isolation the browser supports, the default first.
    pub fn isolations(self) -> &'static [Isolation] {
        match (self.engine(), self.profile_switch()) {
            (Some(Engine::Chromium), Some(ProfileSwitch::Directory)) => &[Isolation::Profile],
            (Some(Engine::Gecko), _) => &[Isolation::Container],
            _ => &[],
        }
    }

    /// Whether macOS opens the browser with `open -a` rather than by running
    /// the program in its bundle, when no profile switch is passed: granted
    /// opens Firefox that way, and Safari, Orion and Arc take no switches.
    fn opens_with_launch_services(self) -> bool {
        matches!(self.engine(), Some(Engine::Gecko | Engine::Webkit)) || self == Self::Arc
    }

    fn install(self) -> Install {
        match self {
            Self::Chrome => Install {
                windows: &[
                    (ProgramFiles, r"Google\Chrome\Application\chrome.exe"),
                    (ProgramFilesX86, r"Google\Chrome\Application\chrome.exe"),
                    (LocalAppData, r"Google\Chrome\Application\chrome.exe"),
                ],
                macos: &[("Google Chrome.app", "Google Chrome")],
                linux: &["google-chrome-stable", "google-chrome", "com.google.Chrome"],
            },
            Self::Edge => Install {
                windows: &[
                    (ProgramFilesX86, r"Microsoft\Edge\Application\msedge.exe"),
                    (ProgramFiles, r"Microsoft\Edge\Application\msedge.exe"),
                ],
                macos: &[("Microsoft Edge.app", "Microsoft Edge")],
                linux: &[
                    "microsoft-edge-stable",
                    "microsoft-edge",
                    "com.microsoft.Edge",
                ],
            },
            Self::Brave => Install {
                windows: &[
                    (
                        ProgramFiles,
                        r"BraveSoftware\Brave-Browser\Application\brave.exe",
                    ),
                    (
                        LocalAppData,
                        r"BraveSoftware\Brave-Browser\Application\brave.exe",
                    ),
                ],
                macos: &[("Brave Browser.app", "Brave Browser")],
                linux: &["brave-browser", "brave", "com.brave.Browser"],
            },
            Self::Vivaldi => Install {
                windows: &[
                    (LocalAppData, r"Vivaldi\Application\vivaldi.exe"),
                    (ProgramFiles, r"Vivaldi\Application\vivaldi.exe"),
                ],
                macos: &[("Vivaldi.app", "Vivaldi")],
                linux: &["vivaldi-stable", "vivaldi", "com.vivaldi.Vivaldi"],
            },
            Self::Chromium => Install {
                windows: &[
                    (LocalAppData, r"Chromium\Application\chrome.exe"),
                    (ProgramFiles, r"Chromium\Application\chrome.exe"),
                ],
                macos: &[("Chromium.app", "Chromium")],
                linux: &[
                    "chromium",
                    "chromium-browser",
                    "ungoogled-chromium",
                    "org.chromium.Chromium",
                    "io.github.ungoogled_software.ungoogled_chromium",
                ],
            },
            Self::Helium => Install {
                windows: &[(LocalAppData, r"imput\Helium\Application\chrome.exe")],
                macos: &[("Helium.app", "Helium")],
                linux: &["helium", "helium-browser", "net.imput.helium"],
            },
            Self::Thorium => Install {
                windows: &[(LocalAppData, r"Thorium\Application\thorium.exe")],
                macos: &[("Thorium.app", "Thorium")],
                linux: &["thorium-browser", "thorium"],
            },
            Self::Opera => Install {
                windows: &[
                    (LocalAppData, r"Programs\Opera\opera.exe"),
                    (ProgramFiles, r"Opera\opera.exe"),
                ],
                macos: &[("Opera.app", "Opera")],
                linux: &["opera", "com.opera.Opera"],
            },
            Self::Arc => Install {
                windows: &[],
                macos: &[("Arc.app", "Arc")],
                linux: &[],
            },
            Self::Firefox => Install {
                windows: &[
                    (ProgramFiles, r"Mozilla Firefox\firefox.exe"),
                    (ProgramFilesX86, r"Mozilla Firefox\firefox.exe"),
                    (ProgramFiles, r"Firefox Developer Edition\firefox.exe"),
                    (ProgramFiles, r"Firefox Nightly\firefox.exe"),
                    (LocalAppData, r"Mozilla Firefox\firefox.exe"),
                ],
                macos: &[
                    ("Firefox.app", "firefox"),
                    ("Firefox Developer Edition.app", "firefox"),
                    ("Firefox Nightly.app", "firefox"),
                ],
                linux: &[
                    "firefox",
                    "firefox-esr",
                    "firefox-developer-edition",
                    "firefox-nightly",
                    "org.mozilla.firefox",
                ],
            },
            Self::Zen => Install {
                windows: &[
                    (ProgramFiles, r"Zen Browser\zen.exe"),
                    (LocalAppData, r"Zen Browser\zen.exe"),
                ],
                macos: &[("Zen.app", "zen"), ("Zen Browser.app", "zen")],
                linux: &["zen-browser", "zen", "app.zen_browser.zen"],
            },
            Self::Librewolf => Install {
                windows: &[
                    (ProgramFiles, r"LibreWolf\librewolf.exe"),
                    (LocalAppData, r"LibreWolf\librewolf.exe"),
                ],
                macos: &[("LibreWolf.app", "librewolf")],
                linux: &["librewolf", "io.gitlab.librewolf-community"],
            },
            Self::Waterfox => Install {
                windows: &[
                    (ProgramFiles, r"Waterfox\waterfox.exe"),
                    (LocalAppData, r"Waterfox\waterfox.exe"),
                ],
                macos: &[("Waterfox.app", "waterfox")],
                linux: &["waterfox", "net.waterfox.waterfox"],
            },
            Self::Floorp => Install {
                windows: &[
                    (ProgramFiles, r"Ablaze Floorp\floorp.exe"),
                    (LocalAppData, r"Ablaze Floorp\floorp.exe"),
                ],
                macos: &[("Floorp.app", "floorp")],
                linux: &["floorp", "one.ablaze.floorp"],
            },
            Self::Safari => Install {
                windows: &[],
                macos: &[("Safari.app", "Safari")],
                linux: &[],
            },
            Self::Orion => Install {
                windows: &[],
                macos: &[("Orion.app", "Orion")],
                linux: &[],
            },
            Self::Command => Install {
                windows: &[],
                macos: &[],
                linux: &[],
            },
        }
    }
}

impl Engine {
    /// The kinds of isolation a browser on this engine supports, the
    /// default first.
    pub fn isolations(self) -> &'static [Isolation] {
        match self {
            Self::Chromium => &[Isolation::Profile],
            Self::Gecko => &[Isolation::Container],
            Self::Webkit => &[],
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Chromium => "chromium",
            Self::Gecko => "gecko",
            Self::Webkit => "webkit",
        }
    }
}

impl Isolation {
    fn as_str(self) -> &'static str {
        match self {
            Self::Profile => "profile",
            Self::Container => "container",
            Self::Off => "none",
        }
    }
}

/// Where a browser was found: the program to run and, on macOS, the app
/// bundle it is in.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Location {
    program: PathBuf,
    bundle: Option<PathBuf>,
}

impl Browser {
    /// The kinds of isolation this browser supports, the default first.
    pub fn isolations(&self) -> &'static [Isolation] {
        match self.kind {
            BrowserType::Command => self.engine.map_or(&[], Engine::isolations),
            kind => kind.isolations(),
        }
    }

    /// How this browser keeps AWS consoles apart: `isolate`, or else the
    /// first kind it supports.
    pub fn isolation(&self) -> Isolation {
        self.isolate
            .or_else(|| self.isolations().first().copied())
            .unwrap_or(Isolation::Off)
    }

    /// The program and its arguments for opening `url`.
    pub fn command_for(&self, url: &str) -> anyhow::Result<(String, Vec<String>)> {
        if self.kind == BrowserType::Command {
            return Ok(self.custom_command(url));
        }
        let location = self.locate()?;
        Ok(self.known_command(&location, url, self.profile.clone(), false))
    }

    /// The program and its arguments for opening `url`, the console of
    /// `profile`. AWS consoles open in the profile's own browser profile or
    /// container as [`Self::isolation`] says: their URL is a federation link
    /// that signs in by itself. Other consoles rely on the sign-in already in
    /// the browser, so they open as [`Self::command_for`] does.
    pub fn console_command_for(
        &self,
        url: &str,
        profile: &Profile,
    ) -> anyhow::Result<(String, Vec<String>)> {
        let isolation = if profile.target.is_aws() {
            self.isolation()
        } else {
            Isolation::Off
        };
        let target = match isolation {
            Isolation::Container => self.container_url(url, profile),
            _ => url.to_string(),
        };
        if self.kind == BrowserType::Command {
            let (program, args) = self.custom_command(&target);
            // The URL's argument, which validation makes sure exists; a
            // wrapper's own arguments (`flatpak run <app>`) come before it.
            let url_at = self.command[1..]
                .iter()
                .position(|arg| arg.contains("{url}"))
                .unwrap_or(args.len());
            return Ok(match isolation {
                Isolation::Profile => (program, isolated_profile_args(args, url_at, &profile.id)),
                _ => (program, args),
            });
        }
        let location = self.locate()?;
        Ok(match isolation {
            Isolation::Profile => self.known_command(
                &location,
                &target,
                Some(chromium_profile_directory(&profile.id)),
                true,
            ),
            _ => self.known_command(&location, &target, self.profile.clone(), false),
        })
    }

    /// `command` with `{url}` replaced by `url`.
    fn custom_command(&self, url: &str) -> (String, Vec<String>) {
        let args = self.command[1..]
            .iter()
            .map(|arg| arg.replace("{url}", url))
            .collect();
        (self.command[0].clone(), args)
    }

    /// How a browser fob knows opens `target` in its profile `profile`;
    /// `fresh` for a profile fob created, which skips the first-run pages.
    fn known_command(
        &self,
        location: &Location,
        target: &str,
        profile: Option<String>,
        fresh: bool,
    ) -> (String, Vec<String>) {
        let switch = self.kind.profile_switch();
        let mut args = Vec::new();
        match (switch, profile) {
            (Some(ProfileSwitch::Directory), Some(profile)) => {
                // Chromium takes switch values only after `=`.
                args.push(format!("--profile-directory={profile}"));
            }
            (Some(ProfileSwitch::Named), Some(profile)) => {
                args.extend(["-P".to_string(), profile]);
            }
            _ => {}
        }
        if fresh {
            args.extend([
                "--no-first-run".to_string(),
                "--no-default-browser-check".to_string(),
            ]);
        }
        if let Some(bundle) = &location.bundle
            && args.is_empty()
            && self.kind.opens_with_launch_services()
        {
            return (
                "open".to_string(),
                vec![
                    "-a".to_string(),
                    bundle.display().to_string(),
                    "-u".to_string(),
                    target.to_string(),
                ],
            );
        }
        args.push(target.to_string());
        (location.program.display().to_string(), args)
    }

    /// The Granted Containers URL that opens `url` in `profile`'s container,
    /// coloured as the first matching style says.
    fn container_url(&self, url: &str, profile: &Profile) -> String {
        let mut container = form_urlencoded::Serializer::new(String::new());
        container
            .append_pair("name", &profile.id)
            .append_pair("url", url);
        let style = self.containers.iter().find(|style| {
            style
                .profiles
                .iter()
                .any(|p| super::matches_pattern(p, &profile.id))
        });
        if let Some(style) = style {
            if let Some(color) = style.color {
                container.append_pair("color", color.as_str());
            }
            if let Some(icon) = style.icon {
                container.append_pair("icon", icon.as_str());
            }
        }
        format!("ext+granted-containers:{}", container.finish())
    }

    /// Where the browser is: `path`, or else the first place its installers
    /// put it on this system.
    fn locate(&self) -> anyhow::Result<Location> {
        if let Some(path) = &self.path {
            return location_from_path(self.kind, path);
        }
        let install = self.kind.install();
        let found = if cfg!(target_os = "macos") {
            let home = std::env::home_dir();
            let dirs = [
                Some(PathBuf::from("/Applications")),
                home.map(|h| h.join("Applications")),
            ];
            find_macos(&install, dirs.iter().flatten().map(PathBuf::as_path))
        } else if cfg!(windows) {
            find_windows(&install, |root| {
                let var = match root {
                    ProgramFiles => "ProgramFiles",
                    ProgramFilesX86 => "ProgramFiles(x86)",
                    LocalAppData => "LOCALAPPDATA",
                };
                std::env::var_os(var).map(PathBuf::from)
            })
        } else if crate::platform::is_wsl() {
            // The Windows browser first: that is the desktop's browser, and
            // it reaches fob's sign-in listener on 127.0.0.1 in WSL. Only
            // where WSL can start Windows programs; otherwise a Linux one.
            crate::platform::wsl_interop()
                .then(|| find_windows(&install, wsl_windows_root))
                .flatten()
                .or_else(|| find_linux(&install))
        } else {
            find_linux(&install)
        };
        found.with_context(|| {
            format!(
                "{} is not installed where fob looks for it; set path in its [browsers] entry",
                self.kind.name()
            )
        })
    }

    pub(super) fn validate(&self) -> Result<(), String> {
        if self.kind == BrowserType::Command {
            self.validate_command()?;
        } else {
            self.validate_known()?;
        }
        self.validate_isolation()?;
        self.validate_containers()
    }

    fn validate_command(&self) -> Result<(), String> {
        if self.path.is_some() || self.profile.is_some() {
            return Err(
                "path and profile are for the browsers fob knows; with type = \"command\", put them in command"
                    .to_string(),
            );
        }
        match self.command.split_first() {
            None => {
                Err("type = \"command\" needs command, the program and its arguments".to_string())
            }
            Some((program, _)) if program.is_empty() => {
                Err("command must name a program".to_string())
            }
            Some((program, _)) if program.contains("{url}") => {
                Err("{url} belongs in an argument, not in the program".to_string())
            }
            Some((_, args)) if !args.iter().any(|arg| arg.contains("{url}")) => {
                Err("command must pass the URL: put {url} in an argument".to_string())
            }
            Some(_) => Ok(()),
        }
    }

    fn validate_known(&self) -> Result<(), String> {
        let name = self.kind.name();
        if !self.command.is_empty() || self.engine.is_some() {
            return Err(format!(
                "fob knows how to open {name}; command and engine are for type = \"command\""
            ));
        }
        if self.path.as_deref().is_some_and(|p| p.trim().is_empty()) {
            return Err("path must not be empty".to_string());
        }
        match &self.profile {
            Some(profile) if profile.trim().is_empty() => {
                Err("profile must not be empty".to_string())
            }
            Some(_) if self.kind.profile_switch().is_none() => Err(format!(
                "{name} cannot be told which of its profiles to open; leave out profile"
            )),
            _ => Ok(()),
        }
    }

    /// Refuses a kind of isolation the browser does not support.
    fn validate_isolation(&self) -> Result<(), String> {
        let Some(isolate) = self.isolate else {
            return Ok(());
        };
        let supported = self.isolations();
        if isolate == Isolation::Off || supported.contains(&isolate) {
            return Ok(());
        }
        let wanted = isolate.as_str();
        Err(match (self.kind, supported.first()) {
            (BrowserType::Command, None) => format!(
                "isolate = \"{wanted}\" needs engine = \"{}\" to say the command runs such a browser",
                match isolate {
                    Isolation::Container => Engine::Gecko.as_str(),
                    _ => Engine::Chromium.as_str(),
                }
            ),
            (BrowserType::Command, Some(default)) => format!(
                "a browser on engine \"{}\" keeps consoles apart with isolate = \"{}\" (the default), not \"{wanted}\"",
                self.engine.map_or("", Engine::as_str),
                default.as_str()
            ),
            (kind, Some(default)) => format!(
                "{} keeps consoles apart with isolate = \"{}\" (the default), not \"{wanted}\"",
                kind.name(),
                default.as_str()
            ),
            (kind, None) => format!(
                "{} cannot keep consoles apart; leave out isolate",
                kind.name()
            ),
        })
    }

    fn validate_containers(&self) -> Result<(), String> {
        if !self.containers.is_empty() && self.isolation() != Isolation::Container {
            return Err(
                "containers style Firefox containers; they need isolate = \"container\", the default for Firefox-based browsers"
                    .to_string(),
            );
        }
        for (i, style) in self.containers.iter().enumerate() {
            if style.profiles.is_empty() {
                return Err(format!(
                    "containers[{i}].profiles must name at least one profile pattern"
                ));
            }
            if let Some(pattern) = style
                .profiles
                .iter()
                .find(|p| p.is_empty() || p.split('/').any(str::is_empty))
            {
                return Err(format!(
                    "containers[{i}].profiles: '{pattern}' has an empty segment; write a profile id such as \"*/prod/*\""
                ));
            }
            if style.color.is_none() && style.icon.is_none() {
                return Err(format!("containers[{i}] must set a color or an icon"));
            }
        }
        Ok(())
    }
}

/// The browser `path` names: a macOS app bundle, the program inside one, or
/// any other program, with `~/` made the home directory.
fn location_from_path(kind: BrowserType, path: &str) -> anyhow::Result<Location> {
    let path = match path.strip_prefix("~/") {
        Some(rest) => std::env::home_dir()
            .filter(|home| home.is_absolute())
            .context("there is no home directory to find ~/ in")?
            .join(rest),
        None => PathBuf::from(path),
    };
    let text = path.to_string_lossy();
    let trimmed = text.trim_end_matches('/');
    if trimmed.ends_with(".app") {
        let bundle = PathBuf::from(trimmed);
        // A renamed or custom bundle (`Google Chrome Canary.app`) names its
        // program in its Info.plist.
        let binary = bundle_executable(&bundle).unwrap_or_else(|| {
            kind.install()
                .macos
                .first()
                .map_or_else(|| kind.name().to_string(), |(_, b)| (*b).to_string())
        });
        return Ok(Location {
            program: bundle.join("Contents/MacOS").join(binary),
            bundle: Some(bundle),
        });
    }
    let bundle = text
        .find(".app/Contents/MacOS/")
        .map(|i| PathBuf::from(&text[..i + ".app".len()]));
    Ok(Location {
        program: path.clone(),
        bundle,
    })
}

/// The program a macOS app bundle runs: `CFBundleExecutable` in its
/// `Contents/Info.plist`, when that is XML, as browsers ship it.
fn bundle_executable(bundle: &Path) -> Option<String> {
    let plist = std::fs::read_to_string(bundle.join("Contents/Info.plist")).ok()?;
    plist_string(&plist, "CFBundleExecutable")
}

/// The `<string>` that follows `<key>key</key>` in an XML property list.
fn plist_string(plist: &str, key: &str) -> Option<String> {
    let after = &plist[plist.find(&format!("<key>{key}</key>"))? + key.len() + 11..];
    let value = after.trim_start().strip_prefix("<string>")?;
    let value = &value[..value.find("</string>")?];
    let value = value.trim().replace("&amp;", "&");
    (!value.is_empty() && !value.contains('/')).then_some(value)
}

fn find_macos<'a>(
    install: &Install,
    dirs: impl Iterator<Item = &'a Path> + Clone,
) -> Option<Location> {
    install.macos.iter().find_map(|(app, binary)| {
        dirs.clone().find_map(|dir| {
            let bundle = dir.join(app);
            let program = bundle.join("Contents/MacOS").join(binary);
            program.is_file().then_some(Location {
                program,
                bundle: Some(bundle),
            })
        })
    })
}

fn find_windows(
    install: &Install,
    root: impl Fn(WindowsRoot) -> Option<PathBuf>,
) -> Option<Location> {
    install.windows.iter().find_map(|(r, relative)| {
        let mut program = root(*r)?;
        program.extend(relative.split('\\'));
        program.is_file().then_some(Location {
            program,
            bundle: None,
        })
    })
}

fn find_linux(install: &Install) -> Option<Location> {
    install.linux.iter().find_map(|name| {
        crate::platform::find_on_path(name).map(|program| Location {
            program,
            bundle: None,
        })
    })
}

/// A Windows install folder as WSL sees it: Program Files on `C:`, where
/// WSL mounts it ([`wsl_c_drive`]); the per-user `%LOCALAPPDATA%` is asked
/// of Windows once, only when a browser is not in Program Files.
fn wsl_windows_root(root: WindowsRoot) -> Option<PathBuf> {
    match root {
        ProgramFiles => Some(wsl_c_drive().join("Program Files")),
        ProgramFilesX86 => Some(wsl_c_drive().join("Program Files (x86)")),
        LocalAppData => {
            static LOCAL_APP_DATA: OnceLock<Option<PathBuf>> = OnceLock::new();
            LOCAL_APP_DATA.get_or_init(wsl_local_app_data).clone()
        }
    }
}

/// Where WSL mounts `C:`: under `/mnt/`, or the `root` of `[automount]` in
/// `/etc/wsl.conf`.
fn wsl_c_drive() -> PathBuf {
    let conf = std::fs::read_to_string("/etc/wsl.conf").unwrap_or_default();
    PathBuf::from(automount_root(&conf).unwrap_or_else(|| "/mnt/".to_string())).join("c")
}

/// The `root` of `[automount]` in a `wsl.conf`'s text, if set.
fn automount_root(conf: &str) -> Option<String> {
    let mut in_automount = false;
    for line in conf.lines() {
        let line = line.split(['#', ';']).next().unwrap_or_default().trim();
        if let Some(section) = line.strip_prefix('[').and_then(|l| l.strip_suffix(']')) {
            in_automount = section.trim().eq_ignore_ascii_case("automount");
        } else if in_automount
            && let Some((key, value)) = line.split_once('=')
            && key.trim().eq_ignore_ascii_case("root")
        {
            let value = value.trim().trim_matches('"');
            return (!value.is_empty()).then(|| value.to_string());
        }
    }
    None
}

fn wsl_local_app_data() -> Option<PathBuf> {
    use std::process::{Command, Stdio};
    if !crate::platform::wsl_interop() {
        return None;
    }
    // cmd.exe warns about a Linux working directory, so start it in C:.
    let output = Command::new("cmd.exe")
        .args(["/d", "/c", "echo %LOCALAPPDATA%"])
        .current_dir(wsl_c_drive())
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .ok()?;
    let windows = String::from_utf8(output.stdout).ok()?.trim().to_string();
    if windows.is_empty() || windows.starts_with('%') {
        return None;
    }
    let output = Command::new("wslpath")
        .args(["-u", &windows])
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .ok()?;
    let linux = String::from_utf8(output.stdout).ok()?.trim().to_string();
    (!linux.is_empty()).then(|| PathBuf::from(linux))
}

/// `args` with the profile folder of fob profile `id` in place of any
/// `--profile-directory` the command names, and without first-run pages.
/// The flags go just before `args[url_at]`, the URL's argument, so a
/// wrapper such as `flatpak run com.google.Chrome {url}` passes them to the
/// browser rather than taking them itself.
fn isolated_profile_args(args: Vec<String>, url_at: usize, id: &str) -> Vec<String> {
    let skipped = ["--no-first-run", "--no-default-browser-check"];
    let flags = [
        format!("--profile-directory={}", chromium_profile_directory(id)),
        skipped[0].to_string(),
        skipped[1].to_string(),
    ];
    let url_at = url_at.min(args.len());
    let mut out = Vec::with_capacity(args.len() + flags.len());
    for (i, arg) in args.into_iter().enumerate() {
        if i == url_at {
            out.extend(flags.iter().cloned());
        }
        if !arg.starts_with("--profile-directory=") && !skipped.contains(&arg.as_str()) {
            out.push(arg);
        }
    }
    if !out.contains(&flags[0]) {
        out.extend(flags);
    }
    out
}

/// The Chromium profile folder for fob profile `id`: `fob` and the id's
/// segments, separated by spaces. Characters a Windows folder name cannot
/// hold become `_`, and trailing dots and spaces, which Windows drops from a
/// folder name, are left out. When either changed the name, a short hash of
/// the id follows, so `acme/Ops.` and `acme/Ops` keep separate folders.
fn chromium_profile_directory(id: &str) -> String {
    let mut dir = String::from("fob");
    for segment in id.split('/') {
        dir.push(' ');
        dir.extend(segment.chars().map(|c| {
            if c.is_control() || matches!(c, '\\' | ':' | '*' | '?' | '"' | '<' | '>' | '|') {
                '_'
            } else {
                c
            }
        }));
    }
    let trimmed = dir.trim_end_matches(['.', ' ']);
    if trimmed == format!("fob {}", id.replace('/', " ")) {
        return dir;
    }
    let digest = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, id.as_bytes());
    let hash: String = digest.as_ref()[..4]
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    format!("{trimmed} {hash}")
}

/// How the Firefox containers of some profiles look, e.g. red with a
/// fingerprint for `*/prod/*`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[cfg_attr(test, derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct ContainerStyle {
    /// Profile ids this applies to, as patterns in which `*` stands for any
    /// characters within one `/`-separated segment, as in `[agent]
    /// profiles`.
    pub profiles: Vec<String>,
    #[serde(default)]
    pub color: Option<ContainerColor>,
    #[serde(default)]
    pub icon: Option<ContainerIcon>,
}

/// The colours Firefox containers come in, as Granted Containers takes them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[cfg_attr(test, derive(schemars::JsonSchema))]
#[serde(rename_all = "lowercase")]
pub enum ContainerColor {
    Blue,
    Turquoise,
    Green,
    Yellow,
    Orange,
    Red,
    Pink,
    Purple,
}

/// The icons Firefox containers come with, as Granted Containers takes them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[cfg_attr(test, derive(schemars::JsonSchema))]
#[serde(rename_all = "lowercase")]
pub enum ContainerIcon {
    Fingerprint,
    Briefcase,
    Dollar,
    Cart,
    Circle,
    Gift,
    Vacation,
    Food,
    Fruit,
    Pet,
    Tree,
    Chill,
}

impl ContainerColor {
    fn as_str(self) -> &'static str {
        match self {
            Self::Blue => "blue",
            Self::Turquoise => "turquoise",
            Self::Green => "green",
            Self::Yellow => "yellow",
            Self::Orange => "orange",
            Self::Red => "red",
            Self::Pink => "pink",
            Self::Purple => "purple",
        }
    }
}

impl ContainerIcon {
    fn as_str(self) -> &'static str {
        match self {
            Self::Fingerprint => "fingerprint",
            Self::Briefcase => "briefcase",
            Self::Dollar => "dollar",
            Self::Cart => "cart",
            Self::Circle => "circle",
            Self::Gift => "gift",
            Self::Vacation => "vacation",
            Self::Food => "food",
            Self::Fruit => "fruit",
            Self::Pet => "pet",
            Self::Tree => "tree",
            Self::Chill => "chill",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::*;

    /// Every browser type, so a test can go through them all.
    const ALL: [BrowserType; 17] = [
        BrowserType::Chrome,
        BrowserType::Edge,
        BrowserType::Brave,
        BrowserType::Vivaldi,
        BrowserType::Chromium,
        BrowserType::Helium,
        BrowserType::Thorium,
        BrowserType::Opera,
        BrowserType::Arc,
        BrowserType::Firefox,
        BrowserType::Zen,
        BrowserType::Librewolf,
        BrowserType::Waterfox,
        BrowserType::Floorp,
        BrowserType::Safari,
        BrowserType::Orion,
        BrowserType::Command,
    ];

    fn aws_profile(id: &str) -> Profile {
        Profile {
            id: id.into(),
            integration: "acme".into(),
            target: crate::Target::Aws {
                account_id: "123456789012".into(),
                account_name: "prod eu".into(),
                role_name: "Admin:Access".into(),
            },
        }
    }

    fn gcp_profile() -> Profile {
        Profile {
            id: "g/proj/user".into(),
            integration: "g".into(),
            target: crate::Target::Gcp {
                project_id: "proj".into(),
                project_name: "proj".into(),
            },
        }
    }

    fn strings(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| (*s).to_string()).collect()
    }

    const URL: &str = "https://signin.aws.amazon.com/federation?Action=login&SigninToken=a+b/c";

    #[test]
    fn integrations_open_in_the_browser_they_name() {
        let config = Config::parse(
            r#"
            [browsers.work]
            type = "chrome"
            path = "/opt/chrome/chrome"
            profile = "Profile 1"

            [integrations.acme]
            type = "aws-sso"
            start_url = "https://acme.awsapps.com/start"
            region = "eu-central-1"
            browser = "work"

            [integrations.google]
            type = "gcp"
            "#,
        )
        .unwrap();
        let browser = config.browser_for("acme").unwrap().unwrap();
        assert_eq!(
            browser.command_for("https://x.test/?a=1").unwrap(),
            (
                "/opt/chrome/chrome".to_string(),
                strings(&["--profile-directory=Profile 1", "https://x.test/?a=1"])
            )
        );
        assert!(config.browser_for("google").unwrap().is_none());
        assert!(config.browser_for("nope").is_err());
    }

    #[test]
    fn a_browser_must_exist_and_be_described_fully() {
        let error = |text: &str| Config::parse(text).unwrap_err().to_string();
        let integration = "[integrations.c]\ntype = \"cloudflare-token\"\nbrowser = \"work\"\n";
        assert_eq!(
            error(integration),
            "integration 'c' opens in browser 'work', which [browsers] does not define (defined: none)"
        );
        for (body, message) in [
            (
                "type = \"command\"",
                "type = \"command\" needs command, the program and its arguments",
            ),
            (
                "type = \"command\"\ncommand = [\"\", \"{url}\"]",
                "command must name a program",
            ),
            (
                "type = \"command\"\ncommand = [\"firefox\"]",
                "command must pass the URL: put {url} in an argument",
            ),
            (
                "type = \"command\"\ncommand = [\"{url}\"]",
                "{url} belongs in an argument, not in the program",
            ),
            (
                "type = \"command\"\ncommand = [\"b\", \"{url}\"]\npath = \"/b\"",
                "path and profile are for the browsers fob knows; with type = \"command\", put them in command",
            ),
            (
                "type = \"zen\"\ncommand = [\"zen\", \"{url}\"]",
                "fob knows how to open Zen; command and engine are for type = \"command\"",
            ),
            (
                "type = \"chrome\"\nengine = \"chromium\"",
                "fob knows how to open Google Chrome; command and engine are for type = \"command\"",
            ),
            (
                "type = \"safari\"\nprofile = \"Work\"",
                "Safari cannot be told which of its profiles to open; leave out profile",
            ),
            (
                "type = \"chrome\"\nprofile = \" \"",
                "profile must not be empty",
            ),
            ("type = \"chrome\"\npath = \"\"", "path must not be empty"),
        ] {
            let text = format!("[browsers.work]\n{body}\n{integration}");
            assert_eq!(error(&text), format!("browser 'work': {message}"), "{body}");
        }
        // A browser without a type, as before 0.12, says what is missing.
        let old = format!("[browsers.work]\ncommand = [\"firefox\", \"{{url}}\"]\n{integration}");
        assert!(format!("{:#}", Config::parse(&old).unwrap_err()).contains("missing field `type`"));
        assert!(
            Config::parse(&format!(
                "[browsers.work]\ntype = \"command\"\ncommand = [\"firefox\", \"--url={{url}}\"]\n{integration}"
            ))
            .is_ok()
        );
    }

    #[test]
    fn isolation_follows_the_browser_type() {
        for kind in ALL {
            let expected: &[Isolation] = match kind {
                BrowserType::Opera
                | BrowserType::Arc
                | BrowserType::Safari
                | BrowserType::Orion
                | BrowserType::Command => &[],
                kind if kind.engine() == Some(Engine::Gecko) => &[Isolation::Container],
                _ => &[Isolation::Profile],
            };
            assert_eq!(kind.isolations(), expected, "{kind:?}");
        }
        let parse = |body: &str| Config::parse(&format!("[browsers.b]\n{body}\n"));
        let isolation = |body: &str| parse(body).unwrap().browsers["b"].isolation();
        assert_eq!(isolation("type = \"edge\""), Isolation::Profile);
        assert_eq!(isolation("type = \"zen\""), Isolation::Container);
        assert_eq!(isolation("type = \"arc\""), Isolation::Off);
        assert_eq!(
            isolation("type = \"zen\"\nisolate = \"none\""),
            Isolation::Off
        );
        assert_eq!(
            isolation("type = \"command\"\ncommand = [\"b\", \"{url}\"]"),
            Isolation::Off
        );
        assert_eq!(
            isolation("type = \"command\"\ncommand = [\"b\", \"{url}\"]\nengine = \"gecko\""),
            Isolation::Container
        );
        assert_eq!(
            isolation("type = \"command\"\ncommand = [\"b\", \"{url}\"]\nengine = \"webkit\""),
            Isolation::Off
        );

        let error = |body: &str| format!("{:#}", parse(body).unwrap_err());
        assert!(
            error("type = \"chrome\"\nisolate = \"container\"").contains(
                "Google Chrome keeps consoles apart with isolate = \"profile\" (the default), not \"container\""
            )
        );
        assert!(
            error("type = \"safari\"\nisolate = \"profile\"")
                .contains("Safari cannot keep consoles apart; leave out isolate")
        );
        assert!(
            error("type = \"command\"\ncommand = [\"b\", \"{url}\"]\nisolate = \"container\"")
                .contains("isolate = \"container\" needs engine = \"gecko\"")
        );
        assert!(
            error("type = \"command\"\ncommand = [\"b\", \"{url}\"]\nengine = \"chromium\"\nisolate = \"container\"")
                .contains("engine \"chromium\" keeps consoles apart with isolate = \"profile\"")
        );
        assert!(error("type = \"firefox\"\nisolate = \"tabs\"").contains("unknown variant `tabs`"));
        assert!(error("type = \"netscape\"").contains("unknown variant `netscape`"));
    }

    #[test]
    fn aws_consoles_open_apart_per_profile() {
        let config = Config::parse(
            r#"
            [browsers.chrome]
            type = "chrome"
            path = "/opt/chrome/chrome"
            profile = "Profile 1"

            [browsers.firefox]
            type = "firefox"
            path = "/usr/bin/firefox"
            profile = "work"

            [browsers.wrapped]
            type = "command"
            command = ["chrome", "--profile-directory=Profile 1", "--no-first-run", "--new-window", "{url}"]
            engine = "chromium"

            [browsers.plain]
            type = "chrome"
            path = "/opt/chrome/chrome"
            isolate = "none"
            "#,
        )
        .unwrap();
        let aws = aws_profile("acme/prod-eu/Admin:Access");
        let access = chromium_profile_directory(&aws.id);
        assert!(
            access.starts_with("fob acme prod-eu Admin_Access "),
            "{access}"
        );
        let console = |name: &str, profile: &Profile| {
            config.browsers[name]
                .console_command_for(URL, profile)
                .unwrap()
        };
        assert_eq!(
            console("chrome", &aws),
            (
                "/opt/chrome/chrome".to_string(),
                strings(&[
                    &format!("--profile-directory={access}"),
                    "--no-first-run",
                    "--no-default-browser-check",
                    URL,
                ])
            )
        );
        assert_eq!(
            console("wrapped", &aws),
            (
                "chrome".to_string(),
                strings(&[
                    "--new-window",
                    &format!("--profile-directory={access}"),
                    "--no-first-run",
                    "--no-default-browser-check",
                    URL,
                ])
            )
        );
        assert_eq!(
            console("plain", &aws),
            ("/opt/chrome/chrome".to_string(), strings(&[URL]))
        );
        // Windows drops trailing dots and spaces from folder names; a hash
        // keeps the names apart that would then be one.
        assert_eq!(
            chromium_profile_directory("acme/prod/Admin"),
            "fob acme prod Admin"
        );
        let ops = chromium_profile_directory("acme/prod/Ops. ");
        assert!(ops.starts_with("fob acme prod Ops "), "{ops}");
        assert_ne!(ops, chromium_profile_directory("acme/prod/Ops."));
        assert_ne!(ops, chromium_profile_directory("acme/prod/Ops"));
        // A wrapper's own arguments stay in front of the profile flags.
        let flatpak = Config::parse(
            r#"
            [browsers.flatpak]
            type = "command"
            command = ["flatpak", "run", "com.google.Chrome", "{url}"]
            engine = "chromium"
            "#,
        )
        .unwrap();
        let (program, args) = flatpak.browsers["flatpak"]
            .console_command_for(URL, &aws)
            .unwrap();
        assert_eq!(program, "flatpak");
        assert_eq!(&args[..2], ["run", "com.google.Chrome"]);
        assert_eq!(args[2], format!("--profile-directory={access}"));
        assert_eq!(args.last().unwrap(), URL);
        let (program, args) = console("firefox", &aws);
        assert_eq!(program, "/usr/bin/firefox");
        assert_eq!(&args[..2], ["-P", "work"]);
        let container = args[2].strip_prefix("ext+granted-containers:").unwrap();
        let params: Vec<(String, String)> = form_urlencoded::parse(container.as_bytes())
            .into_owned()
            .collect();
        assert_eq!(
            params,
            [
                ("name".to_string(), aws.id.clone()),
                ("url".to_string(), URL.to_string())
            ]
        );

        // Other consoles rely on the browser's own sign-in, so they open in
        // the browser profile sign-ins use.
        for browser in config.browsers.values() {
            assert_eq!(
                browser
                    .console_command_for("https://x.test/", &gcp_profile())
                    .unwrap(),
                browser.command_for("https://x.test/").unwrap()
            );
        }
    }

    #[test]
    fn containers_take_the_first_matching_style() {
        let styled = Config::parse(
            r#"
            [browsers.zen]
            type = "zen"
            path = "/opt/zen/zen"

            [[browsers.zen.containers]]
            profiles = ["*/prod-*/*", "*/live/*"]
            color = "red"
            icon = "fingerprint"

            [[browsers.zen.containers]]
            profiles = ["acme/*/*"]
            color = "green"
            "#,
        )
        .unwrap();
        let params = |profile: &Profile| {
            let (_, args) = styled.browsers["zen"]
                .console_command_for(URL, profile)
                .unwrap();
            let container = args[0].strip_prefix("ext+granted-containers:").unwrap();
            form_urlencoded::parse(container.as_bytes())
                .into_owned()
                .filter(|(k, _)| k == "color" || k == "icon")
                .collect::<Vec<_>>()
        };
        let pair = |k: &str, v: &str| (k.to_string(), v.to_string());
        assert_eq!(
            params(&aws_profile("acme/prod-eu/Admin")),
            [pair("color", "red"), pair("icon", "fingerprint")]
        );
        assert_eq!(
            params(&aws_profile("acme/dev/Admin")),
            [pair("color", "green")]
        );
        assert_eq!(params(&aws_profile("other/dev/Admin")), []);

        for (extra, message) in [
            (
                "type = \"chrome\"\n[[browsers.b.containers]]\nprofiles = [\"*\"]\ncolor = \"red\"",
                "they need isolate = \"container\"",
            ),
            (
                "type = \"firefox\"\nisolate = \"none\"\n[[browsers.b.containers]]\nprofiles = [\"*\"]\ncolor = \"red\"",
                "they need isolate = \"container\"",
            ),
            (
                "type = \"firefox\"\n[[browsers.b.containers]]\nprofiles = []\ncolor = \"red\"",
                "containers[0].profiles must name at least one",
            ),
            (
                "type = \"firefox\"\n[[browsers.b.containers]]\nprofiles = [\"a//b\"]\ncolor = \"red\"",
                "has an empty segment",
            ),
            (
                "type = \"firefox\"\n[[browsers.b.containers]]\nprofiles = [\"*\"]",
                "must set a color or an icon",
            ),
            (
                "type = \"firefox\"\n[[browsers.b.containers]]\nprofiles = [\"*\"]\nicon = \"fence\"",
                "unknown variant `fence`",
            ),
        ] {
            let text = format!("[browsers.b]\n{extra}\n");
            let error = format!("{:#}", Config::parse(&text).unwrap_err());
            assert!(error.contains(message), "{extra}: {error}");
        }
    }

    #[test]
    fn macos_opens_firefox_and_webkit_browsers_through_launch_services() {
        let browser = |kind: BrowserType, profile: Option<&str>| Browser {
            kind,
            path: None,
            profile: profile.map(str::to_string),
            command: Vec::new(),
            engine: None,
            isolate: None,
            containers: Vec::new(),
        };
        let location = |app: &str, binary: &str| Location {
            program: PathBuf::from(format!("/Applications/{app}/Contents/MacOS/{binary}")),
            bundle: Some(PathBuf::from(format!("/Applications/{app}"))),
        };
        let firefox = location("Firefox.app", "firefox");
        assert_eq!(
            browser(BrowserType::Firefox, None).known_command(
                &firefox,
                "https://x.test/",
                None,
                false
            ),
            (
                "open".to_string(),
                strings(&["-a", "/Applications/Firefox.app", "-u", "https://x.test/"])
            )
        );
        // A Firefox profile can only be named to the program itself.
        assert_eq!(
            browser(BrowserType::Firefox, Some("work")).known_command(
                &firefox,
                "https://x.test/",
                Some("work".into()),
                false
            ),
            (
                "/Applications/Firefox.app/Contents/MacOS/firefox".to_string(),
                strings(&["-P", "work", "https://x.test/"])
            )
        );
        let safari = location("Safari.app", "Safari");
        assert_eq!(
            browser(BrowserType::Safari, None)
                .known_command(&safari, "https://x.test/", None, false)
                .0,
            "open"
        );
        // Chromium browsers hand the URL to the running instance themselves.
        let chrome = location("Google Chrome.app", "Google Chrome");
        assert_eq!(
            browser(BrowserType::Chrome, None).known_command(
                &chrome,
                "https://x.test/",
                None,
                false
            ),
            (
                "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome".to_string(),
                strings(&["https://x.test/"])
            )
        );
        assert_eq!(
            location_from_path(BrowserType::Zen, "/Applications/Zen.app").unwrap(),
            location("Zen.app", "zen")
        );
        assert_eq!(
            location_from_path(BrowserType::Zen, "/Applications/Zen.app/Contents/MacOS/zen")
                .unwrap(),
            location("Zen.app", "zen")
        );
        assert_eq!(
            location_from_path(BrowserType::Zen, "/usr/bin/zen-browser").unwrap(),
            Location {
                program: PathBuf::from("/usr/bin/zen-browser"),
                bundle: None
            }
        );
    }

    #[test]
    fn browsers_are_found_where_their_installers_put_them() {
        let root = std::env::temp_dir().join(format!("omnifob-browsers-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let file = |relative: &str| {
            let path = root.join(relative);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(&path, "").unwrap();
            path
        };

        // Windows: the per-user install, when Program Files has none.
        let vivaldi = file("local/Vivaldi/Application/vivaldi.exe");
        let windows_root = |r: WindowsRoot| {
            Some(root.join(match r {
                ProgramFiles => "pf",
                ProgramFilesX86 => "pf86",
                LocalAppData => "local",
            }))
        };
        assert_eq!(
            find_windows(&BrowserType::Vivaldi.install(), windows_root).map(|l| l.program),
            Some(vivaldi)
        );
        assert_eq!(
            find_windows(&BrowserType::Chrome.install(), windows_root),
            None
        );

        // macOS: ~/Applications too.
        let zen = file("home/Applications/Zen Browser.app/Contents/MacOS/zen");
        let dirs = [root.join("Applications"), root.join("home/Applications")];
        assert_eq!(
            find_macos(
                &BrowserType::Zen.install(),
                dirs.iter().map(PathBuf::as_path)
            ),
            Some(Location {
                program: zen,
                bundle: Some(root.join("home/Applications/Zen Browser.app")),
            })
        );

        // Firefox installed for one user.
        let firefox = file("local/Mozilla Firefox/firefox.exe");
        assert_eq!(
            find_windows(&BrowserType::Firefox.install(), windows_root).map(|l| l.program),
            Some(firefox)
        );

        // macOS: a custom bundle names its program in Info.plist.
        let canary = root.join("Google Chrome Canary.app");
        file("Google Chrome Canary.app/Contents/MacOS/Google Chrome Canary");
        std::fs::write(
            canary.join("Contents/Info.plist"),
            "<plist><dict>\n\t<key>CFBundleExecutable</key>\n\t<string>Google Chrome Canary</string>\n</dict></plist>",
        )
        .unwrap();
        assert_eq!(
            location_from_path(BrowserType::Chrome, &canary.display().to_string())
                .unwrap()
                .program,
            canary.join("Contents/MacOS/Google Chrome Canary")
        );

        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn wsl_mounts_drives_where_wsl_conf_says() {
        assert_eq!(automount_root(""), None);
        assert_eq!(
            automount_root(
                "[boot]\nroot = /x/\n[automount]\nenabled = true\nroot = \"/win/\" # drives\n"
            ),
            Some("/win/".to_string())
        );
        assert_eq!(automount_root("[automount]\nroot =\n"), None);
    }

    #[test]
    fn every_browser_fob_knows_has_a_name_and_a_place_to_be_found() {
        // The README's table of browsers names every one, by type and name.
        let readme =
            std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("../../README.md"))
                .unwrap();
        for kind in ALL.into_iter().filter(|k| *k != BrowserType::Command) {
            let install = kind.install();
            assert!(
                !install.windows.is_empty()
                    || !install.macos.is_empty()
                    || !install.linux.is_empty(),
                "{kind:?}"
            );
            assert!(kind.engine().is_some(), "{kind:?}");
            let id = format!("{kind:?}").to_lowercase();
            let row = format!("| `{id}` ");
            let line = readme.lines().find(|l| l.starts_with(&row));
            assert!(
                line.is_some_and(|l| l.contains(kind.name())),
                "README's browser table lacks `{id}` ({})",
                kind.name()
            );
        }
    }
}
