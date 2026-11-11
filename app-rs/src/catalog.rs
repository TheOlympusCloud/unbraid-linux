//! Server catalogues published for providers without an API of their own.
//!
//! Server catalogues for providers without a public server API (or as a fallback), from gluetun's monthly-updated,
//! MIT-licensed data: https://github.com/qdm12/gluetun-servers

use crate::error::{Error, Result};
use crate::http;
use crate::model::{City, Country, Location, Server, stable_id};
use indexmap::IndexMap;
use rand::seq::SliceRandom;
use serde::Deserialize;
use std::collections::HashMap;
use std::sync::{LazyLock, PoisonError, RwLock};

const BASE: &str = "https://raw.githubusercontent.com/qdm12/gluetun-servers/main/pkg/servers/";

#[derive(Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(default)]
pub struct Entry {
    pub vpn: String,
    pub country: Option<String>,
    pub region: Option<String>,
    pub city: Option<String>,
    pub server_name: Option<String>,
    pub hostname: String,
    pub wgpubkey: Option<String>,
    pub ips: Vec<String>,
    pub udp: bool,
    pub tcp: bool,
    /// Proton: usable on the free plan.
    pub free: bool,
    /// Live load in percent from a provider's own list; -1 = none (the gluetun catalogue has no load figures).
    pub load: i32,
}

impl Default for Entry {
    fn default() -> Self {
        Entry {
            vpn: String::new(),
            country: None,
            region: None,
            city: None,
            server_name: None,
            hostname: String::new(),
            wgpubkey: None,
            ips: vec![],
            udp: false,
            tcp: false,
            free: false,
            load: -1,
        }
    }
}

impl Entry {
    /// Some providers (Windscribe) only fill `region` with the country.
    pub fn place(&self) -> &str {
        self.country.as_deref().or(self.region.as_deref()).unwrap_or("")
    }

    pub fn ipv4(&self) -> Option<&str> {
        self.ips.iter().find(|ip| ip.contains('.')).map(String::as_str)
    }
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct File {
    timestamp: i64,
    servers: Vec<Entry>,
}

type Published = Box<dyn Fn(&str, i64) + Send + Sync>;
static PUBLISHED: RwLock<Option<Published>> = RwLock::new(None);

/// Told when a catalogue was published (its `timestamp`, epoch seconds) each time one is read, to keep the date. It
/// returns nothing: a date never fails a lookup.
pub fn set_published(f: impl Fn(&str, i64) + Send + Sync + 'static) {
    *PUBLISHED.write().unwrap_or_else(PoisonError::into_inner) = Some(Box::new(f));
}

/// `name` is the gluetun file name, e.g. "protonvpn". `vpn` keeps "wireguard" or "openvpn" servers with an IPv4.
pub fn fetch(name: &str, vpn: &str) -> Result<Vec<Entry>> {
    let f = file(&http::get(&format!("{BASE}{}.json", http::enc(name)), &[], None, None)?)?;
    // Only a time that can be true is kept: after 2020, before tomorrow.
    if (1_577_836_800..=chrono::Utc::now().timestamp() + 86_400).contains(&f.timestamp)
        && let Some(published) = PUBLISHED.read().unwrap_or_else(PoisonError::into_inner).as_ref()
    {
        published(name, f.timestamp);
    }
    Ok(usable(f.servers, vpn))
}

pub fn parse(body: &str, vpn: &str) -> Result<Vec<Entry>> {
    Ok(usable(file(body)?.servers, vpn))
}

pub fn timestamp(body: &str) -> Result<i64> {
    Ok(file(body)?.timestamp)
}

fn file(body: &str) -> Result<File> {
    http::parsed("the server catalogue", || serde_json::from_str(body))
}

fn usable(entries: Vec<Entry>, vpn: &str) -> Vec<Entry> {
    entries
        .into_iter()
        .filter(|e| e.vpn == vpn && e.ipv4().is_some() && !e.place().is_empty() && (vpn != "wireguard" || e.wgpubkey.as_deref().is_some_and(|k| !k.is_empty())))
        .collect()
}

/// Countries with their cities; ids are stable indexes, City.key = city name.
pub fn countries(entries: &[Entry]) -> Vec<Country> {
    let mut places: IndexMap<&str, Vec<&Entry>> = IndexMap::new();
    for e in entries {
        places.entry(e.place()).or_default().push(e);
    }
    places.sort_keys();
    places
        .into_iter()
        .map(|(place, list)| {
            let mut cities: Vec<&str> = list.iter().filter_map(|e| e.city.as_deref()).collect();
            cities.sort();
            cities.dedup();
            Country {
                id: stable_id(place),
                name: place.into(),
                code: code(place),
                server_count: list.len() as i32,
                cities: cities.into_iter().map(|c| City { id: stable_id(c), name: c.into(), key: Some(c.into()) }).collect(),
            }
        })
        .collect()
}

/// Servers for a location, shuffled so equals share the traffic; entries that carry a live [`Entry::load`] come lowest load first.
pub fn pick(entries: &[Entry], loc: &Location) -> Vec<Entry> {
    let mut picked: Vec<Entry> = entries
        .iter()
        .filter(|e| match (&loc.country, &loc.country_code) {
            (Some(country), _) => country == e.place(),
            (None, Some(cc)) => *cc == code(e.place()),
            (None, None) => true,
        })
        .filter(|e| loc.region.is_none() || e.city == loc.region)
        .cloned()
        .collect();
    picked.shuffle(&mut rand::rng());
    picked.sort_by_key(|e| if e.load < 0 { i32::MAX } else { e.load });
    picked
}

/// English country names, normalised ("Hong Kong SAR China" → "hong kong", "Myanmar (Burma)" → "myanmar").
fn norm(name: &str) -> String {
    let n = name.to_lowercase().replace(" & ", " and ").replace('ô', "o");
    let n = n.split(" (").next().unwrap_or_default();
    let n = n.split(", ").next().unwrap_or_default();
    let n = n.strip_suffix(" sar china").unwrap_or(n);
    let n = n.strip_suffix(" darussalam").unwrap_or(n);
    n.strip_prefix("the ").unwrap_or(n).trim().to_string()
}

static CODES: LazyLock<HashMap<String, &str>> = LazyLock::new(|| COUNTRIES.iter().map(|(code, name)| (norm(name), *code)).collect());

#[rustfmt::skip]
const ALIASES: &[(&str, &str)] = &[
    ("usa", "US"), ("united states of america", "US"), ("uk", "GB"), ("great britain", "GB"), ("south korea", "KR"),
    ("turkey", "TR"), ("czech republic", "CZ"), ("macau", "MO"), ("macedonia", "MK"), ("ivory coast", "CI"),
    ("russia", "RU"), ("vietnam", "VN"), ("uae", "AE"), ("bosnia", "BA"), ("cape verde", "CV"), ("eswatini", "SZ"),
    ("democratic republic of the congo", "CD"), ("dr congo", "CD"), ("republic of the congo", "CG"), ("cote d'ivoire", "CI"),
    ("palestine", "PS"), ("brunei", "BN"), ("marocco", "MA"), ("north korea", "KP"), ("syria", "SY"), ("iran", "IR"), ("laos", "LA"),
];

/// ISO code for a catalogue country name; "··" when unknown rather than a plausible-looking wrong code.
pub fn code(country: &str) -> String {
    let n = norm(country);
    CODES.get(&n).copied().or_else(|| ALIASES.iter().find(|(alias, _)| *alias == n).map(|(_, code)| *code)).unwrap_or("··").to_string()
}

/// `e` as a server, named `name` or else its own server name or the first label of its host name. `e` must be usable
/// (have an IPv4 address).
pub fn server(e: &Entry, name: Option<&str>) -> Result<Server> {
    let name = name.map(String::from).or_else(|| e.server_name.clone()).unwrap_or_else(|| e.hostname.split('.').next().unwrap_or_default().to_string());
    // No message of its own: like any other bug, it shows as the caller's fallback text.
    let ip = e.ipv4().ok_or_else(|| Error::State(String::new()))?;
    Ok(Server {
        name,
        host: e.hostname.clone(),
        ip: ip.into(),
        public_key: e.wgpubkey.clone().unwrap_or_default(),
        load: e.load,
        city: e.city.clone().unwrap_or_default(),
        country: code(e.place()),
    })
}

/// The ISO 3166 countries and their English names, as CLDR 42 gives them.
#[rustfmt::skip]
const COUNTRIES: &[(&str, &str)] = &[
    ("AD", "Andorra"), ("AE", "United Arab Emirates"), ("AF", "Afghanistan"), ("AG", "Antigua & Barbuda"),
    ("AI", "Anguilla"), ("AL", "Albania"), ("AM", "Armenia"), ("AO", "Angola"), ("AQ", "Antarctica"),
    ("AR", "Argentina"), ("AS", "American Samoa"), ("AT", "Austria"), ("AU", "Australia"), ("AW", "Aruba"),
    ("AX", "Åland Islands"), ("AZ", "Azerbaijan"), ("BA", "Bosnia & Herzegovina"), ("BB", "Barbados"),
    ("BD", "Bangladesh"), ("BE", "Belgium"), ("BF", "Burkina Faso"), ("BG", "Bulgaria"), ("BH", "Bahrain"),
    ("BI", "Burundi"), ("BJ", "Benin"), ("BL", "St. Barthélemy"), ("BM", "Bermuda"), ("BN", "Brunei"),
    ("BO", "Bolivia"), ("BQ", "Caribbean Netherlands"), ("BR", "Brazil"), ("BS", "Bahamas"), ("BT", "Bhutan"),
    ("BV", "Bouvet Island"), ("BW", "Botswana"), ("BY", "Belarus"), ("BZ", "Belize"), ("CA", "Canada"),
    ("CC", "Cocos (Keeling) Islands"), ("CD", "Congo - Kinshasa"), ("CF", "Central African Republic"),
    ("CG", "Congo - Brazzaville"), ("CH", "Switzerland"), ("CI", "Côte d’Ivoire"), ("CK", "Cook Islands"),
    ("CL", "Chile"), ("CM", "Cameroon"), ("CN", "China"), ("CO", "Colombia"), ("CR", "Costa Rica"), ("CU", "Cuba"),
    ("CV", "Cape Verde"), ("CW", "Curaçao"), ("CX", "Christmas Island"), ("CY", "Cyprus"), ("CZ", "Czechia"),
    ("DE", "Germany"), ("DJ", "Djibouti"), ("DK", "Denmark"), ("DM", "Dominica"), ("DO", "Dominican Republic"),
    ("DZ", "Algeria"), ("EC", "Ecuador"), ("EE", "Estonia"), ("EG", "Egypt"), ("EH", "Western Sahara"),
    ("ER", "Eritrea"), ("ES", "Spain"), ("ET", "Ethiopia"), ("FI", "Finland"), ("FJ", "Fiji"),
    ("FK", "Falkland Islands"), ("FM", "Micronesia"), ("FO", "Faroe Islands"), ("FR", "France"), ("GA", "Gabon"),
    ("GB", "United Kingdom"), ("GD", "Grenada"), ("GE", "Georgia"), ("GF", "French Guiana"), ("GG", "Guernsey"),
    ("GH", "Ghana"), ("GI", "Gibraltar"), ("GL", "Greenland"), ("GM", "Gambia"), ("GN", "Guinea"),
    ("GP", "Guadeloupe"), ("GQ", "Equatorial Guinea"), ("GR", "Greece"),
    ("GS", "South Georgia & South Sandwich Islands"), ("GT", "Guatemala"), ("GU", "Guam"), ("GW", "Guinea-Bissau"),
    ("GY", "Guyana"), ("HK", "Hong Kong SAR China"), ("HM", "Heard & McDonald Islands"), ("HN", "Honduras"),
    ("HR", "Croatia"), ("HT", "Haiti"), ("HU", "Hungary"), ("ID", "Indonesia"), ("IE", "Ireland"), ("IL", "Israel"),
    ("IM", "Isle of Man"), ("IN", "India"), ("IO", "British Indian Ocean Territory"), ("IQ", "Iraq"), ("IR", "Iran"),
    ("IS", "Iceland"), ("IT", "Italy"), ("JE", "Jersey"), ("JM", "Jamaica"), ("JO", "Jordan"), ("JP", "Japan"),
    ("KE", "Kenya"), ("KG", "Kyrgyzstan"), ("KH", "Cambodia"), ("KI", "Kiribati"), ("KM", "Comoros"),
    ("KN", "St. Kitts & Nevis"), ("KP", "North Korea"), ("KR", "South Korea"), ("KW", "Kuwait"),
    ("KY", "Cayman Islands"), ("KZ", "Kazakhstan"), ("LA", "Laos"), ("LB", "Lebanon"), ("LC", "St. Lucia"),
    ("LI", "Liechtenstein"), ("LK", "Sri Lanka"), ("LR", "Liberia"), ("LS", "Lesotho"), ("LT", "Lithuania"),
    ("LU", "Luxembourg"), ("LV", "Latvia"), ("LY", "Libya"), ("MA", "Morocco"), ("MC", "Monaco"), ("MD", "Moldova"),
    ("ME", "Montenegro"), ("MF", "St. Martin"), ("MG", "Madagascar"), ("MH", "Marshall Islands"),
    ("MK", "North Macedonia"), ("ML", "Mali"), ("MM", "Myanmar (Burma)"), ("MN", "Mongolia"),
    ("MO", "Macao SAR China"), ("MP", "Northern Mariana Islands"), ("MQ", "Martinique"), ("MR", "Mauritania"),
    ("MS", "Montserrat"), ("MT", "Malta"), ("MU", "Mauritius"), ("MV", "Maldives"), ("MW", "Malawi"),
    ("MX", "Mexico"), ("MY", "Malaysia"), ("MZ", "Mozambique"), ("NA", "Namibia"), ("NC", "New Caledonia"),
    ("NE", "Niger"), ("NF", "Norfolk Island"), ("NG", "Nigeria"), ("NI", "Nicaragua"), ("NL", "Netherlands"),
    ("NO", "Norway"), ("NP", "Nepal"), ("NR", "Nauru"), ("NU", "Niue"), ("NZ", "New Zealand"), ("OM", "Oman"),
    ("PA", "Panama"), ("PE", "Peru"), ("PF", "French Polynesia"), ("PG", "Papua New Guinea"), ("PH", "Philippines"),
    ("PK", "Pakistan"), ("PL", "Poland"), ("PM", "St. Pierre & Miquelon"), ("PN", "Pitcairn Islands"),
    ("PR", "Puerto Rico"), ("PS", "Palestinian Territories"), ("PT", "Portugal"), ("PW", "Palau"), ("PY", "Paraguay"),
    ("QA", "Qatar"), ("RE", "Réunion"), ("RO", "Romania"), ("RS", "Serbia"), ("RU", "Russia"), ("RW", "Rwanda"),
    ("SA", "Saudi Arabia"), ("SB", "Solomon Islands"), ("SC", "Seychelles"), ("SD", "Sudan"), ("SE", "Sweden"),
    ("SG", "Singapore"), ("SH", "St. Helena"), ("SI", "Slovenia"), ("SJ", "Svalbard & Jan Mayen"), ("SK", "Slovakia"),
    ("SL", "Sierra Leone"), ("SM", "San Marino"), ("SN", "Senegal"), ("SO", "Somalia"), ("SR", "Suriname"),
    ("SS", "South Sudan"), ("ST", "São Tomé & Príncipe"), ("SV", "El Salvador"), ("SX", "Sint Maarten"),
    ("SY", "Syria"), ("SZ", "Eswatini"), ("TC", "Turks & Caicos Islands"), ("TD", "Chad"),
    ("TF", "French Southern Territories"), ("TG", "Togo"), ("TH", "Thailand"), ("TJ", "Tajikistan"),
    ("TK", "Tokelau"), ("TL", "Timor-Leste"), ("TM", "Turkmenistan"), ("TN", "Tunisia"), ("TO", "Tonga"),
    ("TR", "Türkiye"), ("TT", "Trinidad & Tobago"), ("TV", "Tuvalu"), ("TW", "Taiwan"), ("TZ", "Tanzania"),
    ("UA", "Ukraine"), ("UG", "Uganda"), ("UM", "U.S. Outlying Islands"), ("US", "United States"), ("UY", "Uruguay"),
    ("UZ", "Uzbekistan"), ("VA", "Vatican City"), ("VC", "St. Vincent & Grenadines"), ("VE", "Venezuela"),
    ("VG", "British Virgin Islands"), ("VI", "U.S. Virgin Islands"), ("VN", "Vietnam"), ("VU", "Vanuatu"),
    ("WF", "Wallis & Futuna"), ("WS", "Samoa"), ("YE", "Yemen"), ("YT", "Mayotte"), ("ZA", "South Africa"),
    ("ZM", "Zambia"), ("ZW", "Zimbabwe"),
];

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    fn fixture(name: &str) -> String {
        std::fs::read_to_string(format!("{}/tests/fixtures/catalog/{name}", env!("CARGO_MANIFEST_DIR"))).unwrap()
    }

    #[test]
    fn country_codes() {
        for (name, code) in [
            ("Netherlands", "NL"),
            ("United States", "US"),
            ("USA", "US"),
            ("Hong Kong", "HK"),
            ("Macau", "MO"),
            ("Turkey", "TR"),
            ("Myanmar", "MM"),
            ("Czech Republic", "CZ"),
            ("United Kingdom", "GB"),
            ("UK", "GB"),
            ("South Korea", "KR"),
            ("Bosnia and Herzegovina", "BA"),
            ("United Arab Emirates", "AE"),
            ("Italy", "IT"),
            ("Switzerland", "CH"),
            ("Democratic Republic of the Congo", "CD"),
            ("Cote d'Ivoire", "CI"),
            ("Brunei Darussalam", "BN"),
            ("Palestine, State of", "PS"),
            ("Atlantis", "··"),
        ] {
            assert_eq!(code, super::code(name), "{name}");
        }
    }

    #[test]
    fn every_catalogue_country_gets_a_real_iso_code() {
        let iso: HashSet<&str> = COUNTRIES.iter().map(|(code, _)| *code).collect();
        for p in ["protonvpn", "surfshark", "airvpn", "expressvpn"] {
            let vpn = if p == "expressvpn" { "openvpn" } else { "wireguard" };
            let entries = parse(&fixture(&format!("catalog_{p}.json")), vpn).unwrap();
            let bad: Vec<String> =
                countries(&entries).into_iter().filter(|c| !iso.contains(c.code.as_str())).map(|c| format!("{}→{}", c.name, c.code)).collect();
            assert_eq!(Vec::<String>::new(), bad, "{p}: {bad:?}");
        }
    }

    /// The catalogue's publication time is read with it; a catalogue without one says 0 (unknown).
    #[test]
    fn publication_time() {
        assert_eq!(1785990858, timestamp(&fixture("catalog_protonvpn.json")).unwrap());
        assert_eq!(0, timestamp(r#"{"servers":[]}"#).unwrap());
    }
}
