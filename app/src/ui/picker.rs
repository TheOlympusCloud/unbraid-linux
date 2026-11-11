//! The location picker: providers, countries, cities and servers to route through.
//!
//! Two tabs: Providers (the provider and protocol fields, then their locations) and My servers (Tailscale devices and
//! the servers saved in Settings). The country list starts collapsed; a country's cities and servers open beside it.

use crate::model::{Country, Location, Route, Server, Setup, eq_ignore_case};
use crate::providers::{self, Provider, nord::OPEN_VPN_ONLY};
use crate::vpn::TsNode;
use indexmap::{IndexMap, IndexSet};
use regex::Regex;
use std::collections::HashSet;
use std::sync::LazyLock;

/// Nord's server types, as the picker offers them and a route's place names them; none = standard servers.
pub const NORD_GROUPS: [(Option<&str>, &str); 5] = [
    (None, "Standard"),
    (Some("legacy_p2p"), "P2P"),
    (Some("legacy_dedicated_ip"), "Dedicated IP"),
    (Some("legacy_double_vpn"), "Double VPN"),
    (Some("legacy_onion_over_vpn"), "Onion"),
];

/// Nord's protocols and what each is for; none = NordLynx.
const NORD_PROTOCOLS: [(Option<&str>, &str, &str); 3] = [
    (None, "NordLynx", "Fastest. Built on WireGuard"),
    (Some("openvpn_udp"), "OpenVPN UDP", "Wider compatibility"),
    (Some("openvpn_tcp"), "OpenVPN TCP", "For networks that block VPNs"),
];

/// Most servers a manual list shows; NordVPN's comes from its recommendations, best 20 only.
pub const SERVER_LIMIT: usize = 200;

static NODE_NAME: LazyLock<Regex> = LazyLock::new(|| Regex::new("^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$").unwrap());
static DOTTED: LazyLock<Regex> = LazyLock::new(|| Regex::new("^[0-9.]+$").unwrap());

/// A city saved before regions were stored: Mullvad, IVPN and PIA can't tell which city it was, so it must be picked
/// again. Also a pinned favourite saved without its server's address and key (before favourites kept them): star it
/// again.
pub fn stale(l: &Location) -> bool {
    l.provider != "nord" && l.city.is_some() && l.region.is_none() || l.pinned.as_ref().is_some_and(|p| p.host.is_empty())
}

/// A node name, or a Tailscale address: 100.64.0.0/10, so the second octet is 64 to 127.
pub fn valid_node(s: &str) -> bool {
    if !NODE_NAME.is_match(s) {
        return false;
    }
    if !DOTTED.is_match(s) {
        return true;
    }
    let o: Vec<i32> = s.split('.').filter_map(|n| n.parse().ok().filter(|n| (0..=255).contains(n))).collect();
    o.len() == 4 && s.matches('.').count() == 3 && o[0] == 100 && (64..=127).contains(&o[1])
}

/// Up to [`SERVER_LIMIT`] of `loc`'s servers for a manual pick (NordVPN's best 20), least loaded first; none without an
/// account or on a failure. It asks the provider: run it off the window's thread.
pub fn servers(loc: &Location, account: Option<&str>) -> Vec<Server> {
    let (Some(p), Some(account)) = (providers::get(&loc.provider), account) else { return vec![] };
    let limit = if p.id() == "nord" { 20 } else { SERVER_LIMIT };
    let mut list = p.servers(&Location { pinned: None, ..loc.clone() }, account, limit).unwrap_or_default();
    list.sort_by_key(|s| if s.load < 0 { i32::MAX } else { s.load });
    list
}

/// What a click on `l` hands on: a Nord server found over OpenVPN may have no NordLynx key, so under NordLynx its
/// country is picked instead.
pub fn picked(l: &Location) -> Location {
    Location { pinned: l.pinned.clone().filter(|p| l.provider != "nord" || l.protocol.is_some() || !p.public_key.is_empty()), ..l.clone() }
}

/// Why a Tailscale exit can't be chosen while a profile not in use is edited: `r`, a live route, uses another one.
pub fn lock_note(s: &Setup, r: &Route) -> String {
    format!(
        "{} uses the Tailscale exit {}. Tailscale uses one exit node at a time: pick that one here, or this one once this profile is in use.",
        s.profile.as_deref().unwrap_or("The setup in use"),
        r.ts_name.as_deref().or(r.ts_exit.as_deref()).unwrap_or_default(),
    )
}

/// `s` holds `q`, as Kotlin's `contains(q, ignoreCase = true)` finds it: character by character.
fn holds(s: &str, q: &str) -> bool {
    let (s, q): (Vec<char>, Vec<char>) = (s.chars().collect(), q.chars().collect());
    q.is_empty() || s.windows(q.len()).any(|w| w.iter().zip(&q).all(|(a, b)| eq_ignore_case(a.encode_utf8(&mut [0; 4]), b.encode_utf8(&mut [0; 4]))))
}

/// What is open beside the list, or over it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Sheet {
    #[default]
    None,
    /// Route options.
    Options,
    /// A country's cities and servers, by the country's id.
    Country(i32),
}

/// What the picker keeps while it is open: the tab, the search, the provider and the route options chosen, and what
/// is open. A new one each time it opens ([`Picks::open`]).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Picks {
    /// The provider chosen in its field; none shows the route's, else the first signed in.
    pub chosen: Option<String>,
    pub query: String,
    /// Nord's server type and protocol, for the next pick.
    pub group: Option<String>,
    pub protocol: Option<String>,
    /// My servers is open, not Providers.
    pub mine: bool,
    pub all_open: bool,
    pub sheet: Sheet,
    /// The open country's servers show.
    pub servers_open: bool,
    /// Why the Tailscale exit clicked couldn't be chosen ([`lock_note`]).
    pub ts_note: Option<String>,
}

impl Picks {
    /// The picker opening for `target`: on the route's server type and protocol. A route that already uses a Tailscale
    /// exit or a saved server opens on My servers, as does a setup with servers of its own and no provider signed in.
    pub fn open(s: &Setup, target: &str, accounts: &IndexMap<String, String>) -> Picks {
        let route = s.route(Some(target));
        let current = route.filter(|r| !r.imported()).map(|r| &r.loc);
        let none = shown(None, current, &signed(accounts)).is_none();
        Picks {
            group: current.and_then(|c| c.group.clone()),
            protocol: current.and_then(|c| c.protocol.clone()),
            mine: route.is_some_and(Route::imported) || none && (s.tailscale() || !s.servers.is_empty()),
            ..Picks::default()
        }
    }

    /// Another tab: each tab searches only itself, so the search starts over.
    pub fn tab(&mut self, mine: bool) {
        self.mine = mine;
        self.query.clear();
    }

    /// Another provider, from its field: All countries closes.
    pub fn provider(&mut self, id: &str) {
        self.chosen = Some(id.into());
        self.all_open = false;
    }

    /// Opens `sheet`, or closes what is open ([`Sheet::None`]); another country starts with its servers hidden.
    pub fn show(&mut self, sheet: Sheet) {
        let country = |s: Sheet| if let Sheet::Country(id) = s { Some(id) } else { None };
        if country(sheet) != country(self.sheet) {
            self.servers_open = false;
        }
        self.sheet = sheet;
    }

    /// Opens the country of a country row's place ([`PickerView::places`]).
    pub fn open_country(&mut self, l: &Location) {
        if let Some(id) = l.country_id {
            self.show(Sheet::Country(id));
        }
    }

    /// A protocol from its field. It applies to the route at once, keeping its location: what route `target` exits at
    /// then, for a NordVPN route. NordLynx can't carry Double VPN or Onion, so choosing it drops that server type; a
    /// pinned server found over OpenVPN may have no NordLynx key, so it is picked again then.
    pub fn set_protocol(&mut self, s: &Setup, target: &str, p: Option<&str>) -> Option<Location> {
        self.protocol = p.map(str::to_string);
        let current = s.route(Some(target)).filter(|r| !r.imported() && r.loc.provider == "nord").map(|r| &r.loc)?;
        Some(Location {
            protocol: self.protocol.clone(),
            group: current.group.clone().filter(|g| p.is_some() || !OPEN_VPN_ONLY.contains(&g.as_str())),
            pinned: current.pinned.clone().filter(|v| p.is_some() || !v.public_key.is_empty()),
            ..current.clone()
        })
    }
}

/// The providers signed in, in the sign-in list's order.
fn signed(accounts: &IndexMap<String, String>) -> Vec<&'static dyn Provider> {
    providers::all().into_iter().filter(|p| accounts.contains_key(p.id())).collect()
}

/// The provider the picker shows: the one chosen, else the route's, else the first signed in; never one signed out.
fn shown(chosen: Option<&str>, current: Option<&Location>, signed: &[&'static dyn Provider]) -> Option<&'static dyn Provider> {
    let find = |id: &str| signed.iter().copied().find(|p| p.id() == id);
    chosen.and_then(find).or_else(|| current.and_then(|c| find(&c.provider))).or_else(|| signed.first().copied())
}

/// What the picker reads: the store's setup and accounts, the catalogues, the tailnet, and what the window fetched for
/// it.
pub struct Inputs<'a> {
    pub setup: &'a Setup,
    /// What the picker was opened for: "" a new route, "default" the default route of the profile shown, a route's id
    /// (its location), or "app:<key>" (a new route for that app).
    pub target: &'a str,
    pub picks: &'a Picks,
    /// The accounts signed in, by provider id.
    pub accounts: &'a IndexMap<String, String>,
    /// Each provider's countries with their cities.
    pub catalogs: &'a IndexMap<String, Vec<Country>>,
    /// The saved catalogues have been read: an empty list means it couldn't be fetched.
    pub catalogs_read: bool,
    /// Tailnet devices that offer an exit ([`crate::vpn::VpnState::ts_exit_nodes`]).
    pub nodes: &'a [TsNode],
    /// The countries offering [`PickerView::narrow`]'s server type, once fetched; none while unknown.
    pub allowed: Option<&'a IndexSet<String>>,
    /// The servers of [`PickerView::load`], least loaded first ([`servers`]); none while loading.
    pub servers: Option<&'a [Server]>,
}

/// What a row of the picker's lists is.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum PickKind {
    /// A place to pick: Fastest, Direct, a favourite, a country, a city or a server.
    #[default]
    Place,
    /// A section's name, with `action` at its end (the servers' Show or Hide).
    Label,
    /// The open country's name, atop its panel.
    Title,
    /// All countries: `code` is how many, `on` whether they show.
    All,
    /// A note in the page's gutters, in the text's ink when `on`.
    Note,
    /// A quiet line, with its button (`action`): Retry, Add a provider; No matches has none.
    Message,
    /// A Tailscale device offering an exit; `key` is its address.
    Device,
    /// A device typed in the search, which the tailnet hasn't listed: `key` is what was typed.
    Typed,
    /// A server saved in Settings; `key` is its id.
    Server,
    /// Where servers are set up, with Open Settings.
    Settings,
}

/// What a place row has at its start.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Lead {
    #[default]
    None,
    /// The country's code, in an outlined chip.
    Code,
    /// The bolt: any country, picked on connect.
    Fastest,
    Direct,
}

/// One row of the list or of the country's panel.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct PickRow {
    pub kind: PickKind,
    /// What a click acts on: a place's key ([`PickerView::places`]), a device's address, a saved server's id.
    pub key: String,
    pub title: String,
    pub sub: String,
    pub lead: Lead,
    /// The leading chip's code; All countries: how many.
    pub code: String,
    /// The place or exit in use: tinted, with a check. See [`PickKind`] for All countries and notes.
    pub on: bool,
    /// A device: online (offline ones are dim).
    pub online: bool,
    /// The favourite star, and whether it is starred.
    pub star: bool,
    pub starred: bool,
    /// A country's ⋯: its cities and servers, beside the list.
    pub more: bool,
    /// The button at the row's end.
    pub action: String,
    /// A device's or a saved server's place in its group, for the corners.
    pub i: i32,
    pub n: i32,
    /// A server: a smaller row.
    pub small: bool,
}

/// One choice of a field's menu, or a server type's chip. `key` "" is none (NordLynx, Standard).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Choice {
    pub key: String,
    pub label: String,
    pub sub: String,
    pub on: bool,
    pub enabled: bool,
}

/// The provider's own blocking for this route, in Route options.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Blocking {
    pub title: String,
    pub sub: String,
    pub on: bool,
    /// Off while unbraid's own filter replaces it.
    pub enabled: bool,
}

/// Everything the picker shows.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct PickerView {
    pub overline: String,
    pub title: String,
    pub sub: String,
    /// The route's colour: what is in use is tinted with it, the chosen tab too.
    pub hue: i32,
    pub mine: bool,
    /// The provider and protocol fields, on Providers with a provider signed in.
    pub fields: bool,
    /// The provider shown: its id ("" none) and name; the providers signed in, for its menu.
    pub provider_id: String,
    pub provider: String,
    pub providers: Vec<Choice>,
    /// The protocol, and its menu: NordVPN's alone has one, else the field is read-only.
    pub protocol: String,
    pub protocols: Vec<Choice>,
    /// The search, and what it searches.
    pub query: String,
    pub placeholder: String,
    pub rows: Vec<PickRow>,
    /// Route options' value at the bottom ("Standard", "Protection on", "App settings"); "" hides it.
    pub options: String,
    /// The country open beside the list ("" none) and its panel; what the panel says while none is.
    pub country: String,
    pub panel: Vec<PickRow>,
    pub hint: String,
    /// Route options' sheet: Nord's server types (none for other providers) and the provider's blocking.
    pub options_open: bool,
    pub groups: Vec<Choice>,
    pub blocking: Option<Blocking>,
    /// What each place row picks, by its key: the window hands [`picked`] of it on, or stars it as it is.
    pub places: IndexMap<String, Location>,
    /// The provider whose countries the window asks for again: none listed once the saved lists are read.
    pub refresh: Option<String>,
    /// The Nord server type whose countries narrow the list: the window fetches them as [`Inputs::allowed`].
    pub narrow: Option<String>,
    /// The place whose servers the window loads ([`servers`]) as [`Inputs::servers`].
    pub load: Option<Location>,
}

fn label(text: &str) -> PickRow {
    PickRow { kind: PickKind::Label, title: text.into(), ..PickRow::default() }
}

fn note(text: impl Into<String>, on: bool) -> PickRow {
    PickRow { kind: PickKind::Note, title: text.into(), on, ..PickRow::default() }
}

fn message(text: &str, action: &str) -> PickRow {
    PickRow { kind: PickKind::Message, title: text.into(), action: action.into(), ..PickRow::default() }
}

/// The picker's lists as `i` has them.
pub fn view(i: &Inputs) -> PickerView {
    let (s, p, target) = (i.setup, i.picks, i.target);
    let route = s.route(Some(target));
    let current = route.filter(|r| !r.imported()).map(|r| &r.loc);
    let signed = signed(i.accounts);
    let provider = shown(p.chosen.as_deref(), current, &signed);
    let id = provider.map_or("", |x| x.id());
    let nord = id == "nord";
    let group = p.group.clone().filter(|_| nord);
    // Double VPN and Onion only run over OpenVPN: UDP unless TCP was chosen.
    let openvpn_only = group.as_deref().is_some_and(|g| OPEN_VPN_ONLY.contains(&g));
    let protocol = p.protocol.clone().filter(|x| nord && (!openvpn_only || x.starts_with("openvpn"))).or_else(|| (nord && openvpn_only).then(|| "openvpn_udp".into()));
    // Specialty groups exist in a few countries only: list just those.
    let narrow = group.clone().filter(|g| g != "legacy_standard");
    let catalog = provider.and_then(|x| i.catalogs.get(x.id())).map_or(&[][..], Vec::as_slice);
    let countries: Vec<&Country> = match i.allowed.filter(|_| narrow.is_some()) {
        Some(a) => catalog.iter().filter(|c| a.contains(&c.code)).collect(),
        None => catalog.iter().collect(),
    };
    let has_load = provider.is_some_and(|x| x.has_load());
    let query = p.query.trim();
    let hit = |t: &str| query.is_empty() || holds(t, query);
    let on = |l: &Location| current.is_some_and(|c| !stale(l) && c.ident() == l.ident());
    let at = |l: Location| Location { group: group.clone(), protocol: protocol.clone(), ..l };
    let mut seen = HashSet::new();
    let own_favs: Vec<&Location> = s.favorites.iter().filter(|f| f.provider == id && provider.is_some() && !stale(f) && seen.insert(f.fav_key())).collect();
    let mut nodes: Vec<&TsNode> = i.nodes.iter().collect();
    nodes.sort_by_key(|n| !n.online);
    let exit_node = s.routes.iter().find(|r| r.ts_exit.is_some()).and_then(|r| r.ts_name.clone().or_else(|| r.ts_exit.clone()));
    let custom = s.prefs.filter.routes && s.prefs.filter.server().is_some();
    let mut rows = Vec::new();
    let mut places = IndexMap::new();
    let mut place = |rows: &mut Vec<PickRow>, row: PickRow, l: Location| {
        places.insert(row.key.clone(), l);
        rows.push(row);
    };

    let country_row = |c: &Country| {
        let all = at(Location::country(id, c.id, &c.code, &c.name));
        (PickRow { key: format!("c:{}", c.id), lead: Lead::Code, code: c.code.clone(), title: c.name.clone(), on: on(&all), more: true, ..PickRow::default() }, all)
    };
    let favorites = |rows: &mut Vec<PickRow>, place: &mut dyn FnMut(&mut Vec<PickRow>, PickRow, Location), shown: &dyn Fn(&Location) -> bool| {
        let list: Vec<(usize, &&Location)> = own_favs.iter().enumerate().filter(|(_, f)| shown(f)).collect();
        if list.is_empty() {
            return;
        }
        rows.push(label("Favorites"));
        for (n, f) in list {
            let l = Location { group: group.clone(), protocol: protocol.clone(), ..(*f).clone() };
            let row = PickRow { key: format!("fav:{n}"), lead: Lead::Code, code: f.code(), title: f.label(), on: on(&l), star: true, starred: true, ..PickRow::default() };
            place(rows, row, l);
        }
    };
    let tailscale = |rows: &mut Vec<PickRow>, list: &[&TsNode], searching: bool, typed: Option<&str>| {
        if !s.tailscale() {
            return;
        }
        rows.push(label("Tailscale exit node"));
        let said = [
            i.nodes.is_empty().then(|| "Connect and sign in to Tailscale to see your devices.".to_string()),
            exit_node.as_ref().map(|e| format!("One exit node at a time. Choosing another replaces {e}.")),
        ];
        let said = said.into_iter().flatten().collect::<Vec<_>>().join(" ");
        if !said.is_empty() && !searching {
            rows.push(note(said, false));
        }
        for (k, d) in list.iter().enumerate() {
            rows.push(PickRow {
                kind: PickKind::Device,
                key: d.ip.clone(),
                title: d.name.clone(),
                sub: format!("{} · {}", d.ip, if d.online { "online" } else { "offline" }),
                online: d.online,
                on: route.is_some_and(|r| r.ts_exit.as_deref() == Some(d.ip.as_str())),
                i: k as i32,
                n: list.len() as i32,
                ..PickRow::default()
            });
        }
        // A device the tailnet hasn't listed yet (not connected, or just added) can still be named.
        if let Some(t) = typed {
            rows.push(PickRow { kind: PickKind::Typed, key: t.into(), title: format!("Use {t}"), sub: "As this route's Tailscale exit node".into(), n: 1, ..PickRow::default() });
        }
    };
    let saved = |rows: &mut Vec<PickRow>, list: &[&crate::model::OwnServer]| {
        if list.is_empty() {
            return;
        }
        rows.push(label("Saved servers"));
        for (k, v) in list.iter().enumerate() {
            let row = PickRow { kind: PickKind::Server, key: v.id.clone(), title: v.name(), sub: v.kind().into(), code: v.code().into(), i: k as i32, n: list.len() as i32, ..PickRow::default() };
            rows.push(PickRow { on: route.is_some_and(|r| r.own.as_ref() == Some(&v.id)), ..row });
        }
    };

    // An empty profile's default can also be Direct (Routes lists Direct only once an app uses it): on either tab, and
    // with no provider signed in too.
    if query.is_empty() && target == "default" {
        rows.push(PickRow { key: "direct".into(), lead: Lead::Direct, title: "Direct".into(), sub: "No VPN: apps use your normal connection".into(), ..PickRow::default() });
    }
    // Search covers the open tab: favourites, countries and cities, or devices and saved servers.
    if !query.is_empty() && p.mine {
        let devices: Vec<&TsNode> = nodes.iter().copied().filter(|d| hit(&d.name) || hit(&d.ip)).collect();
        let own: Vec<_> = s.servers.iter().filter(|v| hit(&v.name()) || hit(v.kind())).collect();
        let typed = Some(query).filter(|q| s.tailscale() && valid_node(q) && i.nodes.iter().all(|d| d.ip != *q && !eq_ignore_case(&d.name, q)));
        if devices.is_empty() && own.is_empty() && typed.is_none() {
            rows.push(message("No matches", ""));
        }
        if !devices.is_empty() || typed.is_some() {
            tailscale(&mut rows, &devices, true, typed);
        }
        saved(&mut rows, &own);
    } else if !query.is_empty() {
        let by_name: Vec<&Country> = countries.iter().copied().filter(|c| hit(&c.name) || hit(&c.code)).collect();
        let cities: Vec<_> = countries.iter().flat_map(|c| c.cities.iter().filter(|t| hit(&t.name)).map(move |t| (*c, t))).filter(|(c, _)| !by_name.contains(c)).collect();
        if !own_favs.iter().any(|f| hit(&f.label())) && by_name.is_empty() && cities.is_empty() {
            rows.push(message("No matches", ""));
        } else {
            favorites(&mut rows, &mut place, &|f| hit(&f.label()));
            if !by_name.is_empty() || !cities.is_empty() {
                rows.push(label("Locations"));
            }
            for c in by_name {
                let (row, l) = country_row(c);
                place(&mut rows, row, l);
            }
            for (c, t) in cities {
                let l = at(Location { city_id: Some(t.id), city: Some(t.name.clone()), region: t.key.clone(), ..Location::country(id, c.id, &c.code, &c.name) });
                let row = PickRow { key: format!("city:{}:{}", c.id, t.id), lead: Lead::Code, code: c.code.clone(), title: t.name.clone(), sub: c.name.clone(), on: on(&l), ..PickRow::default() };
                place(&mut rows, row, l);
            }
        }
    } else if p.mine {
        if let Some(n) = &p.ts_note {
            rows.push(note(n.clone(), true));
        }
        tailscale(&mut rows, &nodes, false, None);
        saved(&mut rows, &s.servers.iter().collect::<Vec<_>>());
        // Setting servers up happens in Settings; this tab only picks among them.
        let empty = !s.tailscale() && s.servers.is_empty();
        rows.push(PickRow {
            kind: PickKind::Settings,
            title: if empty { "No servers yet. Add a WireGuard, OpenVPN or Shadowsocks server, or turn on Tailscale, in Settings." } else { "Add or manage servers in Settings." }.into(),
            action: "Open Settings".into(),
            ..PickRow::default()
        });
    } else if provider.is_none() {
        rows.push(message("No providers signed in. Sign in to browse their locations.", "Add a provider"));
    } else if countries.is_empty() {
        // While the saved lists are still being read there is nothing to say yet.
        if i.catalogs_read {
            rows.push(message("Server list unavailable. Check the connection.", "Retry"));
        }
    } else {
        let any = at(Location::of(id));
        let row = PickRow { key: "fastest".into(), lead: Lead::Fastest, title: if has_load { "Fastest anywhere" } else { "Automatic" }.into(), sub: "Any country, picked on connect".into(), on: on(&any), ..PickRow::default() };
        place(&mut rows, row, any);
        favorites(&mut rows, &mut place, &|_| true);
        rows.push(PickRow {
            kind: PickKind::All,
            title: "All countries".into(),
            sub: if p.all_open { "" } else { "Click a country to use its fastest server" }.into(),
            code: countries.len().to_string(),
            on: p.all_open,
            ..PickRow::default()
        });
        if p.all_open {
            for c in &countries {
                let (row, l) = country_row(c);
                place(&mut rows, row, l);
            }
        }
    }

    // A country's cities and, on request, its servers, beside the list.
    let country = match p.sheet {
        Sheet::Country(c) => countries.iter().copied().find(|x| x.id == c),
        _ => None,
    };
    let mut panel = Vec::new();
    let mut load = None;
    if let Some(c) = country {
        let all = at(Location::country(id, c.id, &c.code, &c.name));
        let starred = |l: &Location| own_favs.iter().any(|f| f.fav_key() == l.fav_key());
        let row = |key: String, l: &Location, title: String, sub: String| PickRow { key, title, sub, on: on(l), star: true, starred: starred(l), ..PickRow::default() };
        panel.push(PickRow { kind: PickKind::Title, title: c.name.clone(), ..PickRow::default() });
        place(&mut panel, row(format!("in:{}", c.id), &all, format!("{} in {}", if has_load { "Fastest" } else { "Automatic" }, c.name), String::new()), all.clone());
        if c.cities.len() > 1 {
            panel.push(label("Cities"));
            for t in &c.cities {
                let l = Location { city_id: Some(t.id), city: Some(t.name.clone()), region: t.key.clone(), ..all.clone() };
                place(&mut panel, row(format!("in:{}:{}", c.id, t.id), &l, t.name.clone(), String::new()), l);
            }
        }
        panel.push(PickRow { action: if p.servers_open { "Hide" } else { "Show" }.into(), ..label("Servers") });
        if p.servers_open {
            match i.servers {
                None => panel.push(note("Loading servers", false)),
                Some([]) => panel.push(note("No servers found", false)),
                Some(list) => {
                    for (k, v) in list.iter().enumerate() {
                        let l = Location { pinned: Some(v.clone()), ..all.clone() };
                        let sub = [Some(v.city.clone()).filter(|c| !c.trim().is_empty()), (has_load && v.load >= 0).then(|| format!("{}% load", v.load))];
                        let sub = sub.into_iter().flatten().collect::<Vec<_>>().join(" · ");
                        place(&mut panel, PickRow { small: true, ..row(format!("pin:{k}"), &l, v.name.clone(), sub) }, l);
                    }
                }
            }
            load = Some(all);
        }
    }

    let group_label = |g: Option<&str>| NORD_GROUPS.iter().find(|(k, _)| *k == g).map_or_else(|| g.unwrap_or_default().to_string(), |(_, label)| label.to_string());
    let blocker = route.filter(|_| current.is_some_and(|c| c.provider == id)).zip(provider.and_then(|x| x.protection()));
    let options = match () {
        _ if p.mine || !query.is_empty() || provider.is_none() => String::new(),
        _ if nord => group_label(group.as_deref()),
        _ if blocker.is_some() => if blocker.as_ref().is_some_and(|(r, _)| s.protects(r)) && !custom { "Protection on" } else { "Protection off" }.into(),
        _ => "App settings".into(),
    };
    let name = provider.map_or("", |x| x.name());
    PickerView {
        overline: match route {
            Some(r) => format!("{} route · location", r.code()),
            None if target == "default" => "Default route".into(),
            None => "New route".into(),
        },
        title: route.map_or_else(|| "Choose a location".into(), Route::name),
        sub: match current {
            _ if route.is_some_and(|r| r.ts_exit.is_some()) => "Tailscale exit node".into(),
            _ if route.is_some_and(Route::imported) => "Your own server".into(),
            None => "Pick where this route exits".into(),
            Some(c) => {
                let how = c.pinned.is_none().then(|| if has_load { "fastest server" } else { "automatic server" }.to_string());
                [route.map(Route::source), c.pinned.as_ref().map(|v| v.name.clone()).or_else(|| c.city.clone()), how].into_iter().flatten().collect::<Vec<_>>().join(" · ")
            }
        },
        hue: route.map_or(0, |r| r.hue),
        mine: p.mine,
        fields: !p.mine && provider.is_some(),
        provider_id: id.into(),
        provider: name.into(),
        providers: signed.iter().map(|x| Choice { key: x.id().into(), label: x.name().into(), sub: String::new(), on: x.id() == id, enabled: true }).collect(),
        protocol: if nord {
            NORD_PROTOCOLS.iter().find(|(k, _, _)| *k == protocol.as_deref()).map_or_else(|| protocol.clone().unwrap_or_default(), |(_, label, _)| label.to_string())
        } else {
            provider.map(|x| x.protocol()).unwrap_or_default()
        },
        protocols: if nord {
            NORD_PROTOCOLS
                .iter()
                .map(|(k, label, sub)| {
                    let ok = k.is_some() || !openvpn_only;
                    Choice { key: k.unwrap_or_default().into(), label: label.to_string(), sub: if ok { *sub } else { "Double VPN and Onion use OpenVPN" }.into(), on: *k == protocol.as_deref(), enabled: ok }
                })
                .collect()
        } else {
            vec![]
        },
        query: p.query.clone(),
        placeholder: if p.mine { "Server or device" } else { "Country or city" }.into(),
        rows,
        options,
        country: country.map(|c| c.name.clone()).unwrap_or_default(),
        panel,
        hint: format!("Click a country to use its {} server, or its ⋯ to choose a city or a server here.", if has_load { "fastest" } else { "automatic" }),
        options_open: p.sheet == Sheet::Options,
        groups: if nord { NORD_GROUPS.iter().map(|(k, label)| Choice { key: k.unwrap_or_default().into(), label: label.to_string(), sub: String::new(), on: *k == group.as_deref(), enabled: true }).collect() } else { vec![] },
        // unbraid's filter on VPN routes replaces the provider's blocking resolver: shown off, the choice kept.
        blocking: blocker.map(|(r, o)| Blocking {
            title: format!("{name} blocking"),
            sub: if custom { "Off while unbraid's filter is on for VPN routes".into() } else { format!("{} · {}", o.label, if r.filter.is_none() { format!("as set for {name} in Settings") } else { "for this route only".into() }) },
            on: s.protects(r) && !custom,
            enabled: !custom,
        }),
        places,
        refresh: provider.filter(|_| i.catalogs_read && countries.is_empty()).map(|x| x.id().to_string()),
        narrow,
        load,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{City, OwnServer, WgPeer};

    const KEY: &str = "5p4RkybdRU5uaDi90eu4KZPTFif0lKCg4Qp6t1c4F30=";

    /// NordVPN's countries as the approved screenshots list them.
    fn nord_countries() -> Vec<Country> {
        let country = |id: i32, name: &str, code: &str, cities: &[(i32, &str)]| Country {
            id,
            name: name.into(),
            code: code.into(),
            server_count: 0,
            cities: cities.iter().map(|(id, name)| City { id: *id, name: name.to_string(), key: None }).collect(),
        };
        vec![
            country(81, "Germany", "DE", &[(2, "Frankfurt"), (3, "Berlin"), (4, "Hamburg")]),
            country(74, "France", "FR", &[(5, "Paris"), (6, "Marseille")]),
            country(106, "Italy", "IT", &[(15, "Milan"), (16, "Rome")]),
            country(108, "Japan", "JP", &[(14, "Tokyo")]),
            country(153, "Netherlands", "NL", &[(1, "Amsterdam")]),
            country(208, "Sweden", "SE", &[(8, "Stockholm")]),
            country(209, "Switzerland", "CH", &[(7, "Zurich")]),
            country(227, "United Kingdom", "GB", &[(9, "London"), (10, "Manchester")]),
            country(228, "United States", "US", &[(11, "New York"), (12, "Los Angeles"), (13, "Chicago")]),
        ]
    }

    /// The set-up app of the screenshots: three Nord countries and a WireGuard server, Nord signed in.
    fn set_up() -> Setup {
        let lab = WgPeer::new("Home lab", KEY, vec!["10.8.0.2/32".into()], KEY, "203.0.113.7:51820", vec!["0.0.0.0/0".into()]);
        Setup {
            routes: vec![
                Route::new("nl", Location::country("nord", 153, "NL", "Netherlands")),
                Route { hue: 1, ..Route::new("us", Location::country("nord", 228, "US", "United States")) },
                Route { hue: 2, ..Route::new("it", Location::country("nord", 106, "IT", "Italy")) },
                Route { wg: Some(lab), hue: 3, ..Route::new("lab", Location::default()) },
            ],
            ..Setup::default()
        }
    }

    struct World {
        setup: Setup,
        accounts: IndexMap<String, String>,
        catalogs: IndexMap<String, Vec<Country>>,
        nodes: Vec<TsNode>,
        allowed: Option<IndexSet<String>>,
        servers: Option<Vec<Server>>,
    }

    impl World {
        fn new() -> World {
            World {
                setup: set_up(),
                accounts: IndexMap::from([("nord".to_string(), "test".to_string())]),
                catalogs: IndexMap::from([("nord".to_string(), nord_countries())]),
                nodes: vec![],
                allowed: None,
                servers: None,
            }
        }

        fn view(&self, target: &str, p: &Picks) -> PickerView {
            view(&Inputs {
                setup: &self.setup,
                target,
                picks: p,
                accounts: &self.accounts,
                catalogs: &self.catalogs,
                catalogs_read: true,
                nodes: &self.nodes,
                allowed: self.allowed.as_ref(),
                servers: self.servers.as_deref(),
            })
        }

        fn open(&self, target: &str) -> Picks {
            Picks::open(&self.setup, target, &self.accounts)
        }
    }

    fn titles(rows: &[PickRow]) -> Vec<&str> {
        rows.iter().map(|r| r.title.as_str()).collect()
    }

    fn node(name: &str, ip: &str, online: bool) -> TsNode {
        TsNode { name: name.into(), ip: ip.into(), online, id: String::new() }
    }

    #[test]
    fn valid_node_takes_names_and_tailnet_addresses() {
        for ok in ["laptop", "my-pc.tail1234.ts.net", "100.64.0.1", "100.127.255.255", "pi4", &"a".repeat(63)] {
            assert!(valid_node(ok), "{ok}");
        }
        for bad in ["", "-laptop", "my pc", "10.0.0.1", "100.63.0.1", "100.128.0.1", "100.64.0", "100.64.0.256", "100.64..1", &"a".repeat(64)] {
            assert!(!valid_node(bad), "{bad}");
        }
    }

    #[test]
    fn stale_places_are_picked_again() {
        let city = Location { city: Some("Gothenburg".into()), ..Location::country("mullvad", 1, "SE", "Sweden") };
        assert!(stale(&city), "a city saved before regions were");
        assert!(!stale(&Location { region: Some("se-got".into()), ..city.clone() }));
        assert!(!stale(&Location { city: Some("Amsterdam".into()), ..Location::country("nord", 153, "NL", "Netherlands") }), "Nord's cities have ids of their own");
        let pin = |host: &str| Location { pinned: Some(Server { name: "nl1".into(), host: host.into(), ..Server::default() }), ..Location::of("nord") };
        assert!(stale(&pin("")), "a favourite pinned without its address");
        assert!(!stale(&pin("nl1.nordvpn.com")));
    }

    #[test]
    fn holds_ignores_case_as_kotlin_does() {
        assert!(holds("United States", "STAT"));
        assert!(holds("Zürich", "ZÜR"));
        assert!(!holds("Italy", "France"));
        assert!(holds("Italy", ""));
    }

    /// The new route of the approved screenshot: Fastest, the three favourites, All countries closed; Standard.
    #[test]
    fn a_new_route_as_approved() {
        let w = World::new();
        let v = w.view("", &w.open(""));
        assert_eq!(("New route", "Choose a location", "Pick where this route exits"), (v.overline.as_str(), v.title.as_str(), v.sub.as_str()));
        assert!(!v.mine && v.fields);
        assert_eq!(("NordVPN", "NordLynx", "Country or city"), (v.provider.as_str(), v.protocol.as_str(), v.placeholder.as_str()));
        assert_eq!(vec!["Fastest anywhere", "Favorites", "United States", "Italy", "Netherlands", "All countries"], titles(&v.rows));
        let all = &v.rows[5];
        assert_eq!((PickKind::All, "9", "Click a country to use its fastest server", false), (all.kind, all.code.as_str(), all.sub.as_str(), all.on));
        assert!(v.rows[2..5].iter().all(|r| r.star && r.starred && r.lead == Lead::Code && !r.on));
        assert_eq!("Standard", v.options);
        assert_eq!(vec!["Standard", "P2P", "Dedicated IP", "Double VPN", "Onion"], v.groups.iter().map(|g| g.label.as_str()).collect::<Vec<_>>());
        assert_eq!("Click a country to use its fastest server, or its ⋯ to choose a city or a server here.", v.hint);
        assert_eq!(Some(&Location::of("nord")), v.places.get("fastest"));
        assert_eq!((None, None, None), (v.refresh, v.narrow, v.load));
    }

    /// All countries opens the list; a country's ⋯ opens its cities and servers beside it, its servers on request.
    #[test]
    fn a_country_beside_the_list() {
        let mut w = World::new();
        let mut p = w.open("");
        p.all_open = true;
        let v = w.view("", &p);
        assert_eq!(9, v.rows.iter().filter(|r| r.more).count());
        assert!(v.rows.iter().find(|r| r.kind == PickKind::All).is_some_and(|r| r.on && r.sub.is_empty()));
        p.open_country(&v.places["c:81"]);
        let v = w.view("", &p);
        assert_eq!("Germany", v.country);
        assert_eq!(vec!["Germany", "Fastest in Germany", "Cities", "Frankfurt", "Berlin", "Hamburg", "Servers"], titles(&v.panel));
        assert_eq!("Show", v.panel[6].action);
        assert_eq!(Some(2), v.places["in:81:2"].city_id);
        p.servers_open = true;
        assert_eq!(("Hide", "Loading servers"), (w.view("", &p).panel[6].action.as_str(), w.view("", &p).panel[7].title.as_str()));
        let server = |name: &str, load: i32, city: &str| Server { name: name.into(), host: format!("{name}.nordvpn.com"), load, city: city.into(), ..Server::default() };
        w.servers = Some(vec![server("de1012", 9, "Frankfurt"), server("de877", -1, "")]);
        w.setup.favorites.push(Location { pinned: Some(server("de1012", 30, "Frankfurt")), ..Location::country("nord", 81, "DE", "Germany") });
        let v = w.view("", &p);
        let pins: Vec<_> = v.panel.iter().filter(|r| r.small).map(|r| (r.title.as_str(), r.sub.as_str(), r.starred)).collect();
        assert_eq!(vec![("de1012", "Frankfurt · 9% load", true), ("de877", "", false)], pins, "a pin is a favourite by its server's name");
        assert_eq!(Some(&Location::country("nord", 81, "DE", "Germany")), v.load.as_ref());
        // Another country starts with its servers hidden; Route options closes the panel.
        p.show(Sheet::Country(74));
        assert!(!p.servers_open);
        p.show(Sheet::Options);
        let v = w.view("", &p);
        assert!(v.options_open && v.country.is_empty() && v.panel.is_empty());
    }

    /// Search covers the open tab: favourites, then countries by name or code, then cities of the others.
    #[test]
    fn search_finds_favourites_countries_and_cities() {
        let w = World::new();
        let mut p = w.open("");
        p.query = " lAnd ".into();
        let v = w.view("", &p);
        assert_eq!(vec!["Favorites", "Netherlands", "Locations", "Netherlands", "Switzerland"], titles(&v.rows));
        assert_eq!("", v.options, "no Route options while searching");
        p.query = "ham".into();
        let v = w.view("", &p);
        assert_eq!(vec!["Locations", "Hamburg"], titles(&v.rows));
        assert_eq!(("Germany", Some("Hamburg")), (v.rows[1].sub.as_str(), v.places["city:81:4"].city.as_deref()));
        p.query = "us".into();
        assert_eq!(vec!["Locations", "United States"], titles(&w.view("", &p).rows), "a code finds its country");
        p.query = "Atlantis".into();
        assert_eq!(vec!["No matches"], titles(&w.view("", &p).rows));
    }

    /// The route's own location shows as picked, in the route's colour; the header names where it exits.
    #[test]
    fn a_route_shows_where_it_exits() {
        let mut w = World::new();
        let v = w.view("it", &w.open("it"));
        assert_eq!(("IT route · location", "Italy", "Nord · fastest server", 2), (v.overline.as_str(), v.title.as_str(), v.sub.as_str(), v.hue));
        assert_eq!(vec!["Italy"], v.rows.iter().filter(|r| r.on).map(|r| r.title.as_str()).collect::<Vec<_>>());
        w.setup.routes[2].loc = Location { pinned: Some(Server { name: "it201".into(), host: "it201.nordvpn.com".into(), ..Server::default() }), ..w.setup.routes[2].loc.clone() };
        assert_eq!("Nord · it201", w.view("it", &w.open("it")).sub);
        w.setup.routes[2].loc = Location { city: Some("Milan".into()), city_id: Some(15), ..Location::country("nord", 106, "IT", "Italy") };
        assert_eq!("Nord · Milan · fastest server", w.view("it", &w.open("it")).sub);
        let v = w.view("lab", &w.open("lab"));
        assert_eq!(("WG route · location", "Home lab", "Your own server", true), (v.overline.as_str(), v.title.as_str(), v.sub.as_str(), v.mine), "a saved server opens on My servers");
        let v = w.view("default", &w.open("default"));
        assert_eq!(("Default route", "Choose a location"), (v.overline.as_str(), v.title.as_str()));
        assert_eq!((Lead::Direct, "Direct", "No VPN: apps use your normal connection"), (v.rows[0].lead, v.rows[0].title.as_str(), v.rows[0].sub.as_str()));
    }

    /// Double VPN and Onion run over OpenVPN only: UDP unless TCP was chosen, and NordLynx can't be.
    #[test]
    fn nord_server_types_and_protocols() {
        let mut w = World::new();
        let mut p = w.open("");
        p.group = Some("legacy_double_vpn".into());
        let v = w.view("", &p);
        assert_eq!(("OpenVPN UDP", "Double VPN"), (v.protocol.as_str(), v.options.as_str()));
        assert_eq!(Some("legacy_double_vpn"), v.narrow.as_deref());
        let lynx = &v.protocols[0];
        assert_eq!(("NordLynx", "Double VPN and Onion use OpenVPN", false), (lynx.label.as_str(), lynx.sub.as_str(), lynx.enabled));
        assert!(v.protocols[1].on && v.groups[3].on);
        assert_eq!(Some("openvpn_udp"), v.places["fastest"].protocol.as_deref());
        // Specialty groups exist in a few countries only: once known, just those are listed.
        w.allowed = Some(IndexSet::from(["NL".to_string(), "CH".to_string()]));
        p.all_open = true;
        assert_eq!(vec!["Netherlands", "Switzerland"], w.view("", &p).rows.iter().filter(|r| r.more).map(|r| r.title.as_str()).collect::<Vec<_>>());
        p.protocol = Some("openvpn_tcp".into());
        assert_eq!("OpenVPN TCP", w.view("", &p).protocol);
        // Another provider has neither: its protocol is said, not chosen.
        w.accounts.insert("mullvad".into(), "test".into());
        p.provider("mullvad");
        let v = w.view("", &p);
        assert_eq!(("Mullvad", "WireGuard", true), (v.provider.as_str(), v.protocol.as_str(), v.protocols.is_empty()));
        assert!(v.groups.is_empty() && v.narrow.is_none() && !p.all_open);
        assert_eq!(Some("mullvad".to_string()), v.refresh, "no countries listed: asked for again");
        assert_eq!(vec!["Server list unavailable. Check the connection."], titles(&v.rows));
    }

    /// A protocol applies to a Nord route at once: NordLynx drops Double VPN and a pin without its key.
    #[test]
    fn a_protocol_applies_to_the_route() {
        let mut w = World::new();
        let pin = |key: &str| Server { name: "nl1".into(), host: "nl1.nordvpn.com".into(), public_key: key.into(), ..Server::default() };
        w.setup.routes[0].loc = Location { group: Some("legacy_double_vpn".into()), protocol: Some("openvpn_tcp".into()), pinned: Some(pin("")), ..w.setup.routes[0].loc.clone() };
        let mut p = w.open("nl");
        let to = p.set_protocol(&w.setup, "nl", None).unwrap();
        assert_eq!((None, None, None), (to.protocol, to.group, to.pinned));
        let to = p.set_protocol(&w.setup, "nl", Some("openvpn_udp")).unwrap();
        assert_eq!((Some("openvpn_udp"), Some("legacy_double_vpn"), true), (to.protocol.as_deref(), to.group.as_deref(), to.pinned.is_some()));
        w.setup.routes[0].loc.group = None;
        w.setup.routes[0].loc.pinned = Some(pin(KEY));
        assert!(p.set_protocol(&w.setup, "nl", None).unwrap().pinned.is_some(), "a pin with its key stays");
        assert_eq!(None, p.set_protocol(&w.setup, "", Some("openvpn_tcp")), "a new route only remembers it");
        assert_eq!(Some("openvpn_tcp"), p.protocol.as_deref());
    }

    /// A Nord server found over OpenVPN may lack a NordLynx key: under NordLynx its country is picked instead.
    #[test]
    fn picked_drops_a_pin_without_a_nordlynx_key() {
        let pinned = |provider: &str, protocol: Option<&str>, key: &str| Location {
            protocol: protocol.map(str::to_string),
            pinned: Some(Server { name: "x1".into(), host: "x1".into(), public_key: key.into(), ..Server::default() }),
            ..Location::of(provider)
        };
        assert_eq!(None, picked(&pinned("nord", None, "")).pinned);
        assert!(picked(&pinned("nord", Some("openvpn_udp"), "")).pinned.is_some());
        assert!(picked(&pinned("nord", None, KEY)).pinned.is_some());
        assert!(picked(&pinned("mullvad", None, "")).pinned.is_some());
    }

    /// My servers: the tailnet's devices, online first, the saved servers, and where both are set up.
    #[test]
    fn my_servers() {
        let mut w = World::new();
        let mut p = w.open("");
        p.tab(true);
        let v = w.view("", &p);
        assert_eq!(vec!["No servers yet. Add a WireGuard, OpenVPN or Shadowsocks server, or turn on Tailscale, in Settings."], titles(&v.rows));
        assert_eq!(("Server or device", false, ""), (v.placeholder.as_str(), v.fields, v.options.as_str()));
        w.setup.home.tailscale = true;
        w.setup.servers = vec![OwnServer { id: "s1".into(), wg: w.setup.routes[3].wg.clone(), ovpn: None, ss: None }];
        w.setup.routes[3].own = Some("s1".into());
        let v = w.view("lab", &p);
        assert_eq!(vec!["Tailscale exit node", "Connect and sign in to Tailscale to see your devices.", "Saved servers", "Home lab", "Add or manage servers in Settings."], titles(&v.rows));
        assert_eq!(("WireGuard", "WG", true), (v.rows[3].sub.as_str(), v.rows[3].code.as_str(), v.rows[3].on));
        w.nodes = vec![node("nas", "100.101.1.2", false), node("pi", "100.101.1.3", true)];
        w.setup.routes.push(Route { ts_exit: Some("100.101.1.3".into()), ts_name: Some("pi".into()), ..Route::new("ts", Location::default()) });
        let v = w.view("ts", &p);
        assert_eq!(vec!["Tailscale exit node", "One exit node at a time. Choosing another replaces pi.", "pi", "nas"], titles(&v.rows)[..4]);
        assert_eq!(("100.101.1.3 · online", true, true, 0, 2), (v.rows[2].sub.as_str(), v.rows[2].online, v.rows[2].on, v.rows[2].i, v.rows[2].n));
        assert_eq!("Tailscale exit node", v.sub);
        // A device the tailnet hasn't listed can be typed; one it lists, by name or address, isn't offered twice.
        p.query = "100.100.7.7".into();
        let v = w.view("ts", &p);
        assert_eq!(vec!["Tailscale exit node", "Use 100.100.7.7"], titles(&v.rows));
        assert_eq!((PickKind::Typed, "100.100.7.7"), (v.rows[1].kind, v.rows[1].key.as_str()));
        p.query = "PI".into();
        assert_eq!(vec!["Tailscale exit node", "pi"], titles(&w.view("ts", &p).rows));
        p.query = "wireguard".into();
        assert_eq!(vec!["Tailscale exit node", "Use wireguard", "Saved servers", "Home lab"], titles(&w.view("ts", &p).rows), "saved servers are found by their kind");
        p.query = "nothing here!".into();
        assert_eq!(vec!["No matches"], titles(&w.view("ts", &p).rows));
        // While a profile not in use is edited, another live exit keeps this one from being chosen.
        p.query.clear();
        w.setup.profile = Some("Work".into());
        p.ts_note = Some(lock_note(&w.setup, &w.setup.routes[4]));
        let v = w.view("ts", &p);
        assert_eq!(("Work uses the Tailscale exit pi. Tailscale uses one exit node at a time: pick that one here, or this one once this profile is in use.", true), (v.rows[0].title.as_str(), v.rows[0].on));
    }

    /// No provider signed in: Add a provider, or Direct for a default; servers of your own open My servers.
    #[test]
    fn no_provider_signed_in() {
        let mut w = World::new();
        w.accounts.clear();
        let p = w.open("default");
        assert!(!p.mine);
        let v = w.view("default", &p);
        assert_eq!(vec!["Direct", "No providers signed in. Sign in to browse their locations."], titles(&v.rows));
        assert_eq!(("Add a provider", false, ""), (v.rows[1].action.as_str(), v.fields, v.options.as_str()));
        w.setup.home.tailscale = true;
        assert!(w.open("default").mine);
        w.setup.home.tailscale = false;
        w.setup.servers = vec![OwnServer { id: "s1".into(), wg: w.setup.routes[3].wg.clone(), ovpn: None, ss: None }];
        assert!(w.open("").mine);
    }

    /// Route options: a provider's own blocking for this route, off while unbraid's filter replaces it.
    #[test]
    fn route_options_and_blocking() {
        let mut w = World::new();
        w.accounts.insert("mullvad".into(), "test".into());
        w.catalogs.insert("mullvad".into(), nord_countries());
        w.setup.routes.push(Route { hue: 4, ..Route::new("se", Location { region: Some("se-got".into()), ..Location::country("mullvad", 1, "SE", "Sweden") }) });
        let v = w.view("se", &w.open("se"));
        assert_eq!(("Mullvad", "Protection off"), (v.provider.as_str(), v.options.as_str()));
        let b = v.blocking.unwrap();
        assert_eq!(("Mullvad blocking", false, true), (b.title.as_str(), b.on, b.enabled));
        assert!(b.sub.ends_with(" · as set for Mullvad in Settings"), "{}", b.sub);
        w.setup.routes[4].filter = Some(true);
        let v = w.view("se", &w.open("se"));
        assert_eq!(("Protection on", true), (v.options.as_str(), v.blocking.as_ref().unwrap().on));
        assert!(v.blocking.unwrap().sub.ends_with(" · for this route only"));
        w.setup.prefs.filter = crate::model::Filter { id: Some("nextdns".into()), value: "abc123".into(), routes: true, ..Default::default() };
        let v = w.view("se", &w.open("se"));
        let b = v.blocking.unwrap();
        assert_eq!(("Protection off", "Off while unbraid's filter is on for VPN routes", false, false), (v.options.as_str(), b.sub.as_str(), b.on, b.enabled));
        // A new route has no blocking of its own yet; a provider with none offers App settings.
        assert_eq!(None, w.view("", &w.open("")).blocking);
        let mut p = w.open("");
        p.provider("mullvad");
        assert_eq!("App settings", w.view("", &p).options);
    }

    /// A stale favourite isn't listed; two that are the same place show once.
    #[test]
    fn favourites_once_and_fresh() {
        let mut w = World::new();
        w.setup.favorites.push(Location { group: Some("legacy_p2p".into()), ..Location::country("nord", 228, "US", "United States") });
        w.setup.favorites.push(Location { pinned: Some(Server { name: "nl9".into(), ..Server::default() }), ..Location::of("nord") });
        let v = w.view("", &w.open(""));
        assert_eq!(vec!["Fastest anywhere", "Favorites", "United States", "Italy", "Netherlands", "All countries"], titles(&v.rows));
    }
}
