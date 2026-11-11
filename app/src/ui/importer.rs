//! Importing a WireGuard, OpenVPN or Shadowsocks server of your own, from a file or a pasted link: what's checked before
//! a prompt asks for a name or a login, what each prompt says, and the server it saves.

use crate::error::Error;
use crate::manual::{ovpn_weakness, parse_ovpn, parse_ss, ss_weakness};
use crate::model::OwnServer;
use crate::wg_conf;
use std::io::Read;
use std::path::Path;

/// Config files are read up to this size.
pub const CAP: usize = 64 * 1024;
pub const UNREADABLE: &str = "Couldn't read that file. Config files must be under 64 KB.";
/// The file chooser's title.
pub const PICK_TITLE: &str = "Import a WireGuard or OpenVPN config";

/// The text in `path`, or none when it can't be read or is over 64 KB; never reads more than the cap and one byte.
pub fn read_capped(path: &Path) -> Option<String> {
    let mut bytes = Vec::new();
    std::fs::File::open(path).ok()?.take(CAP as u64 + 1).read_to_end(&mut bytes).ok()?;
    (bytes.len() <= CAP).then(|| String::from_utf8_lossy(&bytes).into_owned())
}

/// What a server from `path` is called at first: the file's name without its extension, 40 characters at most.
pub fn file_name(path: &Path) -> String {
    let name = path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
    let short: String = name.rsplit_once('.').map_or(name.as_str(), |(stem, _)| stem).chars().take(40).collect();
    if short.trim().is_empty() { "Imported".into() } else { short }
}

fn message(e: Error) -> String {
    let m = e.to_string();
    if m.trim().is_empty() { "Couldn't read that config".into() } else { m }
}

/// Import prompts waiting for input. In memory only, since they hold passwords and keys.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Draft {
    /// OpenVPN config text and name awaiting a login.
    pub ovpn: Option<(String, String)>,
    pub user: String,
    pub pass: String,
    /// The Shadowsocks link being typed.
    pub link: Option<String>,
    /// A valid WireGuard config waiting for its name.
    pub wg: Option<String>,
    /// What the user calls this server, prefilled from the file name.
    pub name: String,
    /// Why the open prompt's last import failed.
    pub error: Option<String>,
    /// The weak encryption the user was warned about; Import again with the same warning imports anyway.
    pub warning: Option<String>,
    /// What the file chooser was opened for ("wg", "ovpn" or "any"), and the name's prefix, so a file picked later is
    /// read the same way.
    pub kind: String,
    pub prefix: Option<String>,
}

impl Draft {
    /// Closes the prompt and forgets what was typed.
    pub fn clear(&mut self) {
        *self = Draft { kind: std::mem::take(&mut self.kind), prefix: self.prefix.take(), ..Draft::default() };
    }

    /// Before the file chooser opens: `kind` is "wg", "ovpn" or "any"; `prefix` names the server "<prefix> · <file>".
    pub fn file(&mut self, kind: &str, prefix: Option<&str>) {
        self.kind = kind.into();
        self.prefix = prefix.map(str::to_string);
    }

    /// The Shadowsocks prompt, empty.
    pub fn shadowsocks(&mut self) {
        self.clear();
        self.link = Some(String::new());
    }

    /// A file was picked and read (`text`, none if it couldn't be), `file` its [`file_name`]. A broken config fails
    /// here, before the user is asked to name it: the importer's error. Otherwise its prompt opens.
    pub fn picked(&mut self, text: Option<&str>, file: &str) -> Option<String> {
        let Some(text) = text else { return Some(UNREADABLE.into()) };
        let name = self.prefix.as_ref().map_or_else(|| file.to_string(), |p| format!("{p} · {file}"));
        self.clear();
        self.name = name.clone();
        if self.kind == "wg" || (self.kind == "any" && text.to_lowercase().contains("[interface]")) {
            let checked = wg_conf::parse(text, &name).and_then(|p| wg_conf::require_full_tunnel(&p));
            checked.map(|()| self.wg = Some(text.into())).err().map(message)
        } else {
            // A placeholder login: everything but the login is checked before the prompt asks for a name and login.
            parse_ovpn(text, &name, "check", "check").map(|_| self.ovpn = Some((text.into(), name))).err().map(message)
        }
    }

    /// The name typed, or `fallback` when it was left empty.
    fn named(&self, fallback: &str) -> String {
        let n: String = self.name.trim().chars().take(40).collect();
        if n.is_empty() { fallback.into() } else { n }
    }

    /// False the first time `weakness` is seen: the prompt shows it and the next click goes ahead.
    fn accepted(&mut self, weakness: Option<String>) -> bool {
        if weakness.is_none() || weakness == self.warning {
            return true;
        }
        self.warning = weakness;
        false
    }

    /// Import, in the prompt open: the server to save, none while a weakness is shown first, or why it can't (kept in
    /// `error`, the prompt staying open with what was typed). The window saves the server, also on the route the
    /// import is for, then clears the clipboard of [`Draft::secrets`] once it's written, and closes the prompt.
    pub fn import(&mut self) -> Option<OwnServer> {
        let server = |wg, ovpn, ss| OwnServer { id: String::new(), wg, ovpn, ss };
        let made = if let Some(text) = self.wg.clone() {
            wg_conf::parse(&text, &self.named("WireGuard")).map(|p| Some(server(Some(p), None, None)))
        } else if let Some((text, name)) = self.ovpn.clone() {
            parse_ovpn(&text, &self.named(&name), self.user.trim(), &self.pass)
                .and_then(|p| Ok(self.accepted(ovpn_weakness(&p)?).then(|| server(None, Some(p), None))))
        } else if let Some(link) = self.link.clone() {
            parse_ss(link.trim(), &self.named(""))
                .map(|p| self.accepted(ss_weakness(&p)).then(|| server(None, None, Some(p))))
        } else {
            Ok(None)
        };
        made.unwrap_or_else(|e| {
            self.error = Some(message(e));
            None
        })
    }

    /// What may sit on the clipboard from this import: cleared once it's saved, never before, since if the write failed
    /// the clipboard may be the user's only copy.
    pub fn secrets(&self) -> Vec<String> {
        let ovpn = self.ovpn.iter().flat_map(|(text, _)| [text.clone(), self.pass.clone()]);
        self.wg.iter().cloned().chain(ovpn).chain(self.link.iter().cloned()).filter(|s| !s.is_empty()).collect()
    }

    /// A field of the open prompt was edited: its error goes, and a changed link drops the warning too.
    pub fn edited(&mut self, name: &str, user: &str, pass: &str, link: &str) {
        if self.link.as_deref().is_some_and(|l| l != link) {
            self.warning = None;
            self.link = Some(link.into());
        }
        (self.name, self.user, self.pass) = (name.into(), user.into(), pass.into());
        self.error = None;
    }
}

/// The prompt open: `kind` "wg" (a name), "ovpn" (a name and a login) or "ss" (a link and a name), "" none.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct PromptView {
    pub kind: String,
    pub title: String,
    /// Under the title: what the name is for.
    pub text: String,
    pub confirm: String,
    pub danger: bool,
    /// Import can be clicked.
    pub ready: bool,
    /// The name it starts with.
    pub name: String,
    /// "Weak security: …", and why the last import failed; "" none.
    pub warning: String,
    pub error: String,
}

/// Both prompts stay open on a bad input and say why, keeping what was typed.
pub fn prompt(d: &Draft) -> PromptView {
    let (kind, title, text) = match () {
        _ if d.wg.is_some() => ("wg", "Name this server", "Shown on your routes and in Apps. You can rename it later."),
        _ if d.ovpn.is_some() => ("ovpn", "OpenVPN server", ""),
        _ if d.link.is_some() => ("ss", "Shadowsocks link", ""),
        _ => return PromptView::default(),
    };
    let warned = kind != "wg" && d.warning.is_some();
    PromptView {
        kind: kind.into(),
        title: title.into(),
        text: text.into(),
        confirm: if warned { "Import anyway" } else { "Import" }.into(),
        danger: warned,
        ready: d.link.as_deref().is_none_or(|l| !l.trim().is_empty()),
        name: d.name.clone(),
        warning: d.warning.as_ref().filter(|_| kind != "wg").map(|w| format!("Weak security: {w}")).unwrap_or_default(),
        error: d.error.clone().unwrap_or_default(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &str = "5p4RkybdRU5uaDi90eu4KZPTFif0lKCg4Qp6t1c4F30=";

    fn wg(allowed: &str) -> String {
        format!(
            "[Interface]\nPrivateKey = {KEY}\nAddress = 10.8.0.2/32\n\n[Peer]\nPublicKey = {KEY}\nEndpoint = 203.0.113.7:51820\nAllowedIPs = {allowed}\n"
        )
    }

    /// Files over 64 KB aren't read at all; a file's name, without its extension, names the server.
    #[test]
    fn reads_small_files_only() {
        let dir = tempfile::tempdir().unwrap();
        let small = dir.path().join("Home lab.conf");
        std::fs::write(&small, wg("0.0.0.0/0")).unwrap();
        assert_eq!(Some(wg("0.0.0.0/0")), read_capped(&small));
        let big = dir.path().join("big.ovpn");
        std::fs::write(&big, vec![b'#'; CAP + 1]).unwrap();
        assert_eq!(None, read_capped(&big));
        std::fs::write(&big, vec![b'#'; CAP]).unwrap();
        assert!(read_capped(&big).is_some());
        assert_eq!(None, read_capped(&dir.path().join("missing")));
        assert_eq!(
            ("Home lab", "a.b", "Imported", "noext"),
            (
                file_name(&small).as_str(),
                file_name(Path::new("a.b.conf")).as_str(),
                file_name(Path::new(".conf")).as_str(),
                file_name(Path::new("noext")).as_str()
            )
        );
        assert_eq!(40, file_name(Path::new(&format!("{}.conf", "x".repeat(60)))).len());
    }

    /// A WireGuard file opens the name prompt, prefixed from a provider's guide; one that only reaches some addresses
    /// fails before it, and so does a file that couldn't be read.
    #[test]
    fn wireguard_file() {
        let mut d = Draft::default();
        d.file("any", None);
        assert_eq!(None, d.picked(Some(&wg("0.0.0.0/0")), "lab"));
        let p = prompt(&d);
        assert_eq!(
            ("wg", "Name this server", "lab", "Import", true),
            (p.kind.as_str(), p.title.as_str(), p.name.as_str(), p.confirm.as_str(), p.ready)
        );
        d.edited("  My VPS  ", "", "", "");
        let s = d.import().expect("saved");
        assert_eq!(("My VPS", "WireGuard"), (s.name().as_str(), s.kind()));
        assert_eq!(vec![wg("0.0.0.0/0")], d.secrets());
        d.file("wg", Some("PureVPN"));
        assert_eq!(None, d.picked(Some(&wg("0.0.0.0/0")), "nl1"));
        assert_eq!("PureVPN · nl1", d.name);
        assert_eq!(
            Some("This config only reaches 10.0.0.0/8; import it under Settings → Home instead".to_string()),
            d.picked(Some(&wg("10.0.0.0/8")), "lan"),
            "a split tunnel is no route"
        );
        assert_eq!(Some(UNREADABLE.to_string()), d.picked(None, "x"));
    }

    /// Shadowsocks: a weak cipher is said once, and the next Import goes ahead; editing the link asks again.
    #[test]
    fn shadowsocks_weak_cipher() {
        use base64::Engine;
        let link = format!(
            "ss://{}@198.51.100.4:8388#Outline",
            base64::engine::general_purpose::STANDARD.encode("aes-256-cfb:pw")
        );
        let mut d = Draft::default();
        d.shadowsocks();
        assert!(!prompt(&d).ready, "nothing to import yet");
        d.edited("", "", "", &link);
        assert_eq!(None, d.import());
        let p = prompt(&d);
        assert_eq!(("Import anyway", true), (p.confirm.as_str(), p.danger));
        assert!(p.warning.starts_with("Weak security: ") && p.warning.contains("aes-256-cfb"), "{}", p.warning);
        let s = d.import().expect("imported anyway");
        assert_eq!("Outline", s.name());
        d.edited("", "", "", &format!("{link} "));
        assert_eq!(None, d.warning);
        d.edited("", "", "", "ss://nonsense");
        assert_eq!(None, d.import());
        assert!(prompt(&d).error.len() > 5, "the reason stays in the prompt");
    }
}
