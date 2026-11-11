//! Signing in to a provider.
//!
//! On the first run, or as Add provider (from Settings or the picker): step one picks a provider or an import, step two
//! is that provider's form.

use crate::error::Challenge;
use crate::providers::{self, Field};
use indexmap::{IndexMap, IndexSet};

/// Where a form keeps a field's text in the view model: "provider:field".
pub fn form_key(provider: &str, field: &str) -> String {
    format!("{provider}:{field}")
}

/// What the sign-in reads: the accounts, the step shown, and the forms as the view model keeps them.
pub struct Inputs<'a> {
    /// Add provider, from Settings or the picker: Close top-leading. Otherwise the first run, which greets with the logo.
    pub adding: bool,
    /// The accounts signed in, by provider id: those providers aren't offered again.
    pub accounts: &'a IndexMap<String, String>,
    /// What a sign-out couldn't finish, in red until clicked (the view model's notice).
    pub notice: Option<&'a str>,
    /// Why the last import failed (the importer's error).
    pub import_error: Option<&'a str>,
    /// The provider whose form is open; none lists the providers.
    pub step: Option<&'a str>,
    /// The forms' text, by [`form_key`].
    pub form: &'a IndexMap<String, String>,
    /// Providers with a sign-in under way.
    pub signing: &'a IndexSet<String>,
    /// Each provider's last sign-in error, and where the user can fix it (a device list).
    pub errors: &'a IndexMap<String, String>,
    pub links: &'a IndexMap<String, String>,
    /// A question a provider asked before it signs in: a two-factor code, a captcha.
    pub challenges: &'a IndexMap<String, Challenge>,
}

/// A provider not signed in yet, and what its form asks for ("Username · Password").
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ProviderRow {
    pub id: String,
    pub name: String,
    pub fields: String,
}

/// A way in without a provider.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Other {
    /// A WireGuard or OpenVPN config file.
    #[default]
    File,
    Shadowsocks,
    /// Tailscale alone: on the first run only.
    Tailscale,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct OtherRow {
    pub other: Other,
    pub title: String,
    pub sub: String,
}

/// One field of a provider's form.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FormField {
    pub key: String,
    pub label: String,
    pub value: String,
    pub placeholder: String,
    pub secret: bool,
    /// It can be read from a QR code's picture.
    pub qr: bool,
    /// It can hold a whole config file, loaded from disk; `file_note` says whether one was.
    pub file: bool,
    pub file_note: String,
    /// The last field: Enter there sends the form.
    pub last: bool,
    /// The provider's question: its picture (the captcha) shows above it.
    pub asked: bool,
}

/// A provider's form; `id` "" while none is open.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FormView {
    pub id: String,
    pub name: String,
    pub fields: Vec<FormField>,
    /// The captcha, as the PNG the provider sent.
    pub captcha: Option<Vec<u8>>,
    pub error: String,
    /// `error` is the provider's question: it reads as an instruction, not in red.
    pub question: bool,
    /// Where the user can fix the error, and the button that opens it.
    pub link: String,
    pub link_label: String,
    pub help: String,
    /// Every field is filled: Continue can send it.
    pub ready: bool,
    /// The sign-in is under way.
    pub busy: bool,
    /// The sign-in landed: Add provider closes.
    pub done: bool,
}

/// Everything the sign-in shows.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SignInView {
    pub overline: String,
    pub title: String,
    pub sub: String,
    /// Close top-leading (Add provider).
    pub closable: bool,
    pub notice: String,
    pub providers: Vec<ProviderRow>,
    pub others: Vec<OtherRow>,
    pub import_error: String,
    pub form: FormView,
}

/// What provider `id`'s form asks: its own fields, then the provider's question, answered and sent with the rest.
fn fields(i: &Inputs, id: &str) -> Vec<Field> {
    let mut f = providers::get(id).map(|p| p.fields()).unwrap_or_default();
    f.extend(i.challenges.get(id).map(|c| c.field.clone()));
    f
}

fn text<'a>(i: &'a Inputs, id: &str, key: &str) -> &'a str {
    i.form.get(&form_key(id, key)).map_or("", String::as_str)
}

/// The answers Continue sends for the open form, as typed (the view model trims what isn't secret); none while it is
/// incomplete or already under way.
pub fn submit(i: &Inputs) -> Option<IndexMap<String, String>> {
    let id = i.step?;
    let f = fields(i, id);
    let ready = f.iter().all(|f| !text(i, id, &f.key).trim().is_empty());
    (ready && !i.signing.contains(id))
        .then(|| f.iter().map(|f| (f.key.clone(), text(i, id, &f.key).to_string())).collect())
}

/// The sign-in as `i` has it: the providers to choose from, or the open one's form.
pub fn view(i: &Inputs) -> SignInView {
    let other = |other, title: &str, sub: &str| OtherRow { other, title: title.into(), sub: sub.into() };
    let mut others = vec![
        other(Other::File, "Import a config file", "WireGuard .conf or OpenVPN .ovpn"),
        other(Other::Shadowsocks, "Shadowsocks link", "Paste an ss:// access key"),
    ];
    if !i.adding {
        others.push(other(Other::Tailscale, "Tailscale only", "No VPN provider, just your tailnet"));
    }
    let form = i.step.and_then(providers::get).map(|p| {
        let id = p.id();
        let asked = i.challenges.get(id);
        let list = fields(i, id);
        let n = list.len();
        FormView {
            id: id.into(),
            name: p.name().into(),
            fields: list
                .iter()
                .enumerate()
                .map(|(k, f)| {
                    let value = text(i, id, &f.key).to_string();
                    FormField {
                        key: f.key.clone(),
                        label: f.label.clone(),
                        placeholder: if f.hint.trim().is_empty() { f.label.clone() } else { f.hint.clone() },
                        secret: f.secret,
                        qr: f.qr,
                        file: f.file,
                        // Config files keep their line breaks only when loaded from a file.
                        file_note: if value.contains('\n') {
                            "Config file loaded"
                        } else {
                            "Or load the downloaded file"
                        }
                        .into(),
                        last: k + 1 == n,
                        asked: asked.is_some_and(|c| c.field == *f),
                        value,
                    }
                })
                .collect(),
            captcha: asked.and_then(|c| c.image.clone()),
            error: i.errors.get(id).cloned().unwrap_or_default(),
            question: asked.is_some(),
            link: i.links.get(id).cloned().unwrap_or_default(),
            link_label: format!("Open the {} client area", p.name()),
            help: format!("{} Stored encrypted on this computer.", p.help()),
            ready: list.iter().all(|f| !text(i, id, &f.key).trim().is_empty()),
            busy: i.signing.contains(id),
            done: i.accounts.contains_key(id),
        }
    });
    SignInView {
        // First run greets with the logo; adding one later is an ordinary page with Close top-leading.
        overline: if i.adding { "Providers & servers" } else { "Sign in" }.into(),
        title: if i.adding { "Add provider" } else { "un/braid" }.into(),
        sub: "Choose your VPN".into(),
        closable: i.adding,
        notice: i.notice.unwrap_or_default().into(),
        providers: providers::all()
            .into_iter()
            .filter(|p| !i.accounts.contains_key(p.id()))
            .map(|p| ProviderRow {
                id: p.id().into(),
                name: p.name().into(),
                fields: p.fields().iter().map(|f| f.label.as_str()).collect::<Vec<_>>().join(" · "),
            })
            .collect(),
        others,
        import_error: i.import_error.unwrap_or_default().into(),
        form: form.unwrap_or_default(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct World {
        adding: bool,
        accounts: IndexMap<String, String>,
        step: Option<String>,
        form: IndexMap<String, String>,
        signing: IndexSet<String>,
        errors: IndexMap<String, String>,
        links: IndexMap<String, String>,
        challenges: IndexMap<String, Challenge>,
    }

    impl World {
        fn inputs(&self) -> Inputs<'_> {
            Inputs {
                adding: self.adding,
                accounts: &self.accounts,
                notice: None,
                import_error: None,
                step: self.step.as_deref(),
                form: &self.form,
                signing: &self.signing,
                errors: &self.errors,
                links: &self.links,
                challenges: &self.challenges,
            }
        }
    }

    /// The first run, as approved: every provider with what it asks, then the other ways in, Tailscale alone too.
    #[test]
    fn the_first_run_lists_every_provider() {
        let v = view(&World::default().inputs());
        assert_eq!(
            ("Sign in", "un/braid", "Choose your VPN", false),
            (v.overline.as_str(), v.title.as_str(), v.sub.as_str(), v.closable)
        );
        let rows: Vec<_> = v.providers.iter().map(|p| (p.name.as_str(), p.fields.as_str())).collect();
        assert_eq!(
            vec![
                ("NordVPN", "Access token"),
                ("Mullvad", "Account number"),
                ("Private Internet Access", "Username · Password"),
                ("IVPN", "Account ID"),
                ("Proton VPN", "WireGuard key or .conf"),
                ("Proton VPN Free", "WireGuard key or .conf"),
                ("Surfshark", "WireGuard key or .conf"),
                ("ExpressVPN", "Username · Password"),
                ("Windscribe", "WireGuard config"),
                ("AirVPN", "API key or WireGuard .conf"),
            ],
            rows
        );
        assert_eq!(
            vec![Other::File, Other::Shadowsocks, Other::Tailscale],
            v.others.iter().map(|o| o.other).collect::<Vec<_>>()
        );
        assert_eq!("", v.form.id);
    }

    /// Add provider: Close, no Tailscale alone, and no provider already signed in.
    #[test]
    fn adding_offers_the_others() {
        let w = World {
            adding: true,
            accounts: IndexMap::from([("nord".to_string(), "x".to_string())]),
            ..World::default()
        };
        let v = view(&w.inputs());
        assert_eq!(("Providers & servers", "Add provider", true), (v.overline.as_str(), v.title.as_str(), v.closable));
        assert_eq!("Mullvad", v.providers[0].name);
        assert_eq!(2, v.others.len());
    }

    /// A form: its fields with their hints, ready once each is filled, sent as typed; not while one is under way.
    #[test]
    fn a_form_is_ready_once_filled() {
        let mut w = World { step: Some("pia".into()), ..World::default() };
        let v = view(&w.inputs()).form;
        assert_eq!(("pia", "Private Internet Access", false), (v.id.as_str(), v.name.as_str(), v.ready));
        let f: Vec<_> = v.fields.iter().map(|f| (f.label.as_str(), f.placeholder.as_str(), f.secret, f.last)).collect();
        assert_eq!(vec![("Username", "p1234567", false, false), ("Password", "PIA password", true, true)], f);
        assert!(v.help.ends_with(" Stored encrypted on this computer."), "{}", v.help);
        w.form.insert(form_key("pia", "username"), " p1234567 ".into());
        w.form.insert(form_key("pia", "password"), "   ".into());
        assert!(!view(&w.inputs()).form.ready && submit(&w.inputs()).is_none(), "blank isn't filled");
        w.form.insert(form_key("pia", "password"), " s3cret ".into());
        assert!(view(&w.inputs()).form.ready);
        let sent = submit(&w.inputs()).unwrap();
        assert_eq!(
            (" p1234567 ", " s3cret "),
            (sent["username"].as_str(), sent["password"].as_str()),
            "as typed: secrets are never trimmed"
        );
        w.signing.insert("pia".into());
        assert!(view(&w.inputs()).form.busy && submit(&w.inputs()).is_none());
        w.accounts.insert("pia".into(), "x".into());
        assert!(view(&w.inputs()).form.done);
    }

    /// A question the provider asked is one more field, with its picture; its message reads as an instruction.
    #[test]
    fn a_question_is_one_more_field() {
        let mut w = World { step: Some("ivpn".into()), ..World::default() };
        w.form.insert(form_key("ivpn", "account"), "i-AB12-CD34-EF56".into());
        let field = Field { secret: false, ..Field::new("captcha", "Characters in the picture") };
        w.challenges.insert(
            "ivpn".into(),
            Challenge {
                message: "Type the characters".into(),
                field,
                image: Some(vec![0x89, b'P']),
                keep: IndexMap::new(),
            },
        );
        w.errors.insert("ivpn".into(), "Type the characters".into());
        let v = view(&w.inputs()).form;
        assert_eq!(
            vec![("account", true, false, false), ("captcha", false, true, true)],
            v.fields.iter().map(|f| (f.key.as_str(), f.qr, f.asked, f.last)).collect::<Vec<_>>()
        );
        assert_eq!(
            ("Characters in the picture", true, Some(vec![0x89, b'P']), false),
            (v.fields[1].placeholder.as_str(), v.question, v.captcha, v.ready)
        );
        w.form.insert(form_key("ivpn", "captcha"), "x7Kq".into());
        assert_eq!(Some("x7Kq"), submit(&w.inputs()).as_ref().and_then(|a| a.get("captcha")).map(String::as_str));
        // Any other failure: in red, with where to fix it.
        w.challenges.clear();
        w.errors.insert("ivpn".into(), "This account has no free device slot".into());
        w.links.insert("ivpn".into(), "https://www.ivpn.net/account/".into());
        let v = view(&w.inputs()).form;
        assert_eq!(
            (false, "https://www.ivpn.net/account/", "Open the IVPN client area"),
            (v.question, v.link.as_str(), v.link_label.as_str())
        );
    }

    /// A field that holds a config file says whether one was loaded: only a file keeps its line breaks.
    #[test]
    fn a_config_file_field_says_when_one_is_loaded() {
        let mut w = World { step: Some("windscribe".into()), ..World::default() };
        assert_eq!(
            (true, "Or load the downloaded file"),
            (view(&w.inputs()).form.fields[0].file, view(&w.inputs()).form.fields[0].file_note.as_str())
        );
        w.form.insert(form_key("windscribe", "config"), "[Interface]\nPrivateKey = x\n".into());
        assert_eq!("Config file loaded", view(&w.inputs()).form.fields[0].file_note);
    }
}
