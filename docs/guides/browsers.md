# Browsers

Sign-ins and consoles open in the system's default browser. To keep each identity's sessions in a browser, or a browser profile, of its own, define the browsers once and name one in each integration with `browser`; it applies to `fob login` and `fob console` alike, and integrations without it keep the default.

## Defining browsers

```toml
[browsers.work]
type = "chrome"            # fob finds it, also Windows Chrome from WSL
profile = "Profile 1"      # optional: the Chrome profile folder sign-ins use, as chrome://version shows it

[browsers.personal]
type = "zen"
profile = "personal"       # optional: the Firefox profile name

[integrations.acme]
type = "aws-sso"
start_url = "https://acme.awsapps.com/start"
sso_region = "eu-central-1"
browser = "work"
```

## Finding the browser

`type` names the browser. fob looks for it where its installers put it: Program Files and `%LOCALAPPDATA%` on Windows (from WSL too, before any Linux browser, since the Windows browser is the desktop's), `/Applications` and `~/Applications` on macOS, and the program names below on `PATH` on Linux, Flatpak app ids included. Set `path` when it is elsewhere: an absolute path (a macOS `.app` bundle or the program in it), one under `~/`, or a name on `PATH`. A sign-in must still open on this machine, since the browser returns to a listener on `127.0.0.1`.

## Consoles kept apart

The AWS console signs out one identity when another signs in, so a second profile's console would log out the first. fob opens each AWS profile's console apart from the others, in the way the browser supports:

| `type`      | Browser        | Engine   | Linux programs                                       | Consoles kept apart |
| ----------- | -------------- | -------- | ---------------------------------------------------- | ------------------- |
| `chrome`    | Google Chrome  | Chromium | `google-chrome-stable`, `google-chrome`              | `profile`           |
| `edge`      | Microsoft Edge | Chromium | `microsoft-edge-stable`, `microsoft-edge`            | `profile`           |
| `brave`     | Brave          | Chromium | `brave-browser`, `brave`                             | `profile`           |
| `vivaldi`   | Vivaldi        | Chromium | `vivaldi-stable`, `vivaldi`                          | `profile`           |
| `chromium`  | Chromium       | Chromium | `chromium`, `chromium-browser`, `ungoogled-chromium` | `profile`           |
| `helium`    | Helium         | Chromium | `helium`, `helium-browser`                           | `profile`           |
| `thorium`   | Thorium        | Chromium | `thorium-browser`, `thorium`                         | `profile`           |
| `opera`     | Opera          | Chromium | `opera`                                              | no                  |
| `arc`       | Arc            | Chromium | (macOS only)                                         | no                  |
| `firefox`   | Firefox        | Gecko    | `firefox`, `firefox-esr`, Developer Edition, Nightly | `container`         |
| `zen`       | Zen            | Gecko    | `zen-browser`, `zen`                                 | `container`         |
| `librewolf` | LibreWolf      | Gecko    | `librewolf`                                          | `container`         |
| `waterfox`  | Waterfox       | Gecko    | `waterfox`                                           | `container`         |
| `floorp`    | Floorp         | Gecko    | `floorp`                                             | `container`         |
| `safari`    | Safari         | WebKit   | (macOS only)                                         | no                  |
| `orion`     | Orion          | WebKit   | (macOS only)                                         | no                  |

- `profile`: a browser profile per fob profile, `--profile-directory=fob <integration> <account> <role>`, which the browser creates on first use and reuses after; delete one in the browser's profile manager. A profile id with characters a Windows folder name cannot hold, or a trailing dot, gets a short hash after its name so no two profiles share a folder.
- `container`: a container (Firefox's Container Tabs) per fob profile, opened as `ext+granted-containers:name=<profile id>&url=<console URL>`. It needs the [Granted Containers](https://addons.mozilla.org/en-US/firefox/addon/granted/) add-on in that browser, which creates the container, named after the profile, the first time.

`isolate = "none"` opens every console in the browser profile sign-ins use instead. Asking a browser for a kind of isolation it does not have (`isolate = "container"` on Chrome) fails when the config loads. fob knows no reliable command-line switch for Opera's and Arc's profiles, and Safari and Orion take none, so their consoles are not kept apart. Sign-ins and other providers' consoles open in the browser profile `profile` names, since they rely on the session already there.

## Any other browser

Any other browser, a Flatpak or Snap wrapper or a script, is `type = "command"`: the program and its arguments, run without a shell, with `{url}` in any argument replaced by the URL. `engine` says what the browser is built on, which gives its consoles that engine's isolation (`chromium`: `profile`, replacing any `--profile-directory` in the command; `gecko`: `container`; `webkit`: none); without it they are not kept apart.

```toml
[browsers.flatpak-firefox]
type = "command"
command = ["flatpak", "run", "org.mozilla.firefox", "-P", "work", "{url}"]
engine = "gecko"
```

## Container colours and icons

Containers can be told apart at a glance by colour and icon, set per profile pattern (`*` matches within one part of the id, as in `[agent] profiles`); the first entry that matches wins, and unmatched containers get the add-on's own colour:

```toml
[[browsers.personal.containers]]
profiles = ["*/prod/*", "*/prod-*/*"]
color = "red"         # blue, turquoise, green, yellow, orange, red, pink or purple
icon = "fingerprint"  # fingerprint, briefcase, dollar, cart, circle, gift, vacation, food, fruit, pet, tree or chill

[[browsers.personal.containers]]
profiles = ["*/dev/*"]
color = "green"
```

fob adds them to the URL as `color` and `icon`, which Granted Containers applies when it creates the container.
