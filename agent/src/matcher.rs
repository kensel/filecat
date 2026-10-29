//! The rollup matcher, the wire policy id and the sticky-redaction HMAC (docs/rollups.md, sections
//! 2 and 3.7), and the policy a connection holds. Conformance vectors:
//! tests/data/rollup_match_vectors.json, run by the tests below.

use crate::proto::{hex, storage_name, unhex, Fail, Obj, R};
use hmac::{Hmac, Mac};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::HashSet;

pub const MAX_RULES: usize = 1024;
pub const MAX_PATTERN_BYTES: usize = 4096;
pub const MAX_PATTERNS_BYTES: usize = 64 * 1024;
pub const MAX_REDACTION: usize = 10_000;

fn eq(a: char, b: char, fold: bool) -> bool {
    a == b || (fold && a.is_ascii() && b.is_ascii() && a.eq_ignore_ascii_case(&b))
}

/// `?` is one character, `*` any run of characters; both inside one path component.
fn glob(p: &[char], s: &[char], fold: bool) -> bool {
    let (mut pi, mut si) = (0usize, 0usize);
    let mut star: Option<usize> = None;
    let mut mark = 0usize;
    while si < s.len() {
        if pi < p.len() && (p[pi] == '?' || eq(p[pi], s[si], fold)) && p[pi] != '*' {
            pi += 1;
            si += 1;
        } else if pi < p.len() && p[pi] == '*' {
            star = Some(pi);
            mark = si;
            pi += 1;
        } else if let Some(st) = star {
            pi = st + 1;
            mark += 1;
            si = mark;
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == '*' {
        pi += 1;
    }
    pi == p.len()
}

#[derive(Debug, Clone)]
enum Comp {
    Lit(Vec<char>),
    /// `**` as a whole component; `last` means one or more components, else zero or more.
    Star2 { last: bool },
}

#[derive(Debug, Clone)]
enum Form {
    Name(Vec<char>),
    Path(Vec<Comp>),
}

/// One compiled pattern. No separator: a name pattern. Otherwise a path pattern (a leading `**/`
/// makes it a suffix pattern: `**` there matches zero or more leading components).
#[derive(Debug, Clone)]
pub struct Pattern {
    form: Form,
    fold: bool,
}

/// What a pattern is matched against: a child's name and its absolute path, in the catalog's
/// spelling of names.
pub struct Subject {
    name: Vec<char>,
    comps: Vec<Vec<char>>,
    pub is_dir: bool,
}

impl Subject {
    pub fn new(name: &[u8], path: &str, is_dir: bool) -> Subject {
        Subject {
            name: storage_name(name).chars().collect(),
            comps: path.split('/').filter(|c| !c.is_empty()).map(|c| c.chars().collect()).collect(),
            is_dir,
        }
    }
    /// A path relative to some folder: the name is its last component.
    pub fn from_rel(rel: &str, is_dir: bool) -> Subject {
        let comps: Vec<Vec<char>> = rel.split('/').filter(|c| !c.is_empty()).map(|c| c.chars().collect()).collect();
        Subject { name: comps.last().cloned().unwrap_or_default(), comps, is_dir }
    }
}

impl Pattern {
    pub fn new(pattern: &str, insensitive: bool) -> Pattern {
        let form = if !pattern.contains('/') {
            Form::Name(pattern.chars().collect())
        } else {
            let comps: Vec<&str> = pattern.split('/').filter(|c| !c.is_empty()).collect();
            let n = comps.len();
            Form::Path(
                comps
                    .iter()
                    .enumerate()
                    .map(|(i, c)| if *c == "**" { Comp::Star2 { last: i == n - 1 } } else { Comp::Lit(c.chars().collect()) })
                    .collect(),
            )
        };
        Pattern { form, fold: insensitive }
    }

    pub fn matches(&self, s: &Subject) -> bool {
        match &self.form {
            Form::Name(p) => glob(p, &s.name, self.fold),
            Form::Path(p) => rec(p, &s.comps, self.fold),
        }
    }
}

fn rec(p: &[Comp], s: &[Vec<char>], fold: bool) -> bool {
    match p.first() {
        None => s.is_empty(),
        Some(Comp::Lit(g)) => !s.is_empty() && glob(g, &s[0], fold) && rec(&p[1..], &s[1..], fold),
        Some(Comp::Star2 { last }) => {
            let min = usize::from(*last);
            (min..=s.len()).any(|k| rec(&p[1..], &s[k..], fold))
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Ty {
    Any,
    Dir,
    File,
}

#[derive(Debug, Clone)]
pub struct Rule {
    pub id: Value,
    pub tag: Option<String>,
    pub ty: Ty,
    pub keep: bool,
    pub private: bool,
    pub suggest: bool,
    patterns: Vec<Pattern>,
}

impl Rule {
    pub fn matches(&self, s: &Subject) -> bool {
        match self.ty {
            Ty::Dir if !s.is_dir => return false,
            Ty::File if s.is_dir => return false,
            _ => {}
        }
        self.patterns.iter().any(|p| p.matches(s))
    }
}

fn valid_tag(tag: &str) -> bool {
    let b = tag.as_bytes();
    if b.len() < 3 || b[0] != b'[' || b[b.len() - 1] != b']' {
        return false;
    }
    let inner = &b[1..b.len() - 1];
    inner.len() <= 32
        && inner[0].is_ascii_uppercase()
        && inner.iter().all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || *c == b'_' || *c == b'-')
}

fn parse_rule(raw: &Value) -> R<Rule> {
    let o = raw.as_object().ok_or_else(|| Fail::bad("a rule must be an object"))?;
    let flag = |k: &str| o.get(k).and_then(Value::as_bool).unwrap_or(false);
    let ty = match o.get("type").and_then(Value::as_str).unwrap_or("any") {
        "any" => Ty::Any,
        "dir" => Ty::Dir,
        "file" => Ty::File,
        other => return Err(Fail::bad(format!("unknown rule type {other:?}"))),
    };
    let insensitive = match o.get("case").and_then(Value::as_str).unwrap_or("sensitive") {
        "sensitive" => false,
        "insensitive" => true,
        other => return Err(Fail::bad(format!("unknown rule case {other:?}"))),
    };
    let keep = flag("keep");
    let tag = match o.get("tag") {
        Some(Value::String(t)) if !keep => {
            if !valid_tag(t) {
                return Err(Fail::bad(format!("bad tag {t:?}")));
            }
            Some(t.clone())
        }
        _ => None,
    };
    if tag.is_none() && !keep {
        return Err(Fail::bad("a rule needs a tag unless it is a keep rule"));
    }
    let mut patterns = Vec::new();
    if let Some(m) = o.get("match") {
        for p in m.as_array().ok_or_else(|| Fail::bad("match must be an array"))? {
            patterns.push(Pattern::new(p.as_str().ok_or_else(|| Fail::bad("a pattern must be a string"))?, insensitive));
        }
    }
    Ok(Rule { id: o.get("id").cloned().unwrap_or(Value::Null), tag, ty, keep, private: flag("private"), suggest: flag("suggest"), patterns })
}

#[derive(Debug, Clone)]
pub struct Marker {
    pub name: Vec<u8>,
    pub tag: String,
    pub private: bool,
}

#[derive(Debug, Clone)]
pub struct RedactRoot {
    pub root: String,
    pub base: String,
    pub hashes: HashSet<String>,
    pub inodes: HashSet<(u64, u64)>,
}

/// A connection's policy (`configure_policy`).
#[derive(Debug, Default, Clone)]
pub struct Policy {
    pub exclude: HashSet<Vec<u8>>,
    pub rules: Vec<Rule>,
    pub markers: Vec<Marker>,
    pub key: Option<Vec<u8>>,
    pub redact_roots: Vec<RedactRoot>,
    pub id: String,
}

impl Policy {
    pub fn has_rules(&self) -> bool {
        !self.rules.is_empty() || !self.markers.is_empty()
    }
    pub fn excluded(&self, name: &[u8], vpath: &[u8]) -> bool {
        !self.exclude.is_empty() && (self.exclude.contains(name) || self.exclude.contains(vpath))
    }
}

/// The first 12 hex digits of the SHA-256 of the compact JSON of `[rules, marker names]`, each
/// rule as `{"tag","match","type","case","keep","private","suggest"}`.
pub fn policy_id(rules: &[Value], marker_names: &[String]) -> String {
    let js = |s: &str| serde_json::to_string(s).unwrap_or_default();
    let mut out = String::from("[[");
    for (i, r) in rules.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        let tag = match r.get("tag") {
            Some(Value::String(t)) => js(t),
            _ => "null".to_string(),
        };
        let pats: Vec<String> = r.get("match").and_then(Value::as_array).map(|a| a.iter().map(|p| js(p.as_str().unwrap_or(""))).collect()).unwrap_or_default();
        let b = |k: &str| if r.get(k).and_then(Value::as_bool).unwrap_or(false) { "true" } else { "false" };
        out.push_str(&format!(
            "{{\"tag\":{},\"match\":[{}],\"type\":{},\"case\":{},\"keep\":{},\"private\":{},\"suggest\":{}}}",
            tag,
            pats.join(","),
            js(r.get("type").and_then(Value::as_str).unwrap_or("any")),
            js(r.get("case").and_then(Value::as_str).unwrap_or("sensitive")),
            b("keep"),
            b("private"),
            b("suggest")
        ));
    }
    out.push_str("],[");
    out.push_str(&marker_names.iter().map(|m| js(m)).collect::<Vec<_>>().join(","));
    out.push_str("]]");
    hex(&Sha256::digest(out.as_bytes()))[..12].to_string()
}

/// `HMAC-SHA256(key, "filecat-redact-v1" NUL root NUL rel)`, hex of the first 16 bytes.
pub fn redaction_hash(key: &[u8], root: &str, rel: &str) -> String {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key).expect("HMAC takes any key length");
    mac.update(b"filecat-redact-v1\0");
    mac.update(root.as_bytes());
    mac.update(b"\0");
    mac.update(rel.as_bytes());
    hex(&mac.finalize().into_bytes()[..16])
}

/// Parse and validate the `policy` object of `configure_policy`.
pub fn configure(raw: &Obj) -> R<Policy> {
    let empty = Vec::new();
    let rules_raw = match raw.get("rules") {
        Some(Value::Array(a)) => a,
        None | Some(Value::Null) => &empty,
        _ => return Err(Fail::bad("rules must be an array")),
    };
    if rules_raw.len() > MAX_RULES {
        return Err(Fail::bad("too many rules"));
    }
    let mut total = 0usize;
    for r in rules_raw {
        if let Some(m) = r.get("match").and_then(Value::as_array) {
            for p in m {
                let n = p.as_str().map(str::len).unwrap_or(0);
                if n > MAX_PATTERN_BYTES {
                    return Err(Fail::bad("pattern too long"));
                }
                total += n;
            }
        }
    }
    if total > MAX_PATTERNS_BYTES {
        return Err(Fail::bad("patterns too big"));
    }
    let rules = rules_raw.iter().map(parse_rule).collect::<R<Vec<_>>>()?;

    let mut markers = Vec::new();
    if let Some(Value::Array(ms)) = raw.get("markers") {
        for m in ms {
            let name = m.get("name").and_then(Value::as_str).unwrap_or("");
            let tag = m.get("tag").and_then(Value::as_str).unwrap_or("");
            if name.is_empty() || name == "." || name == ".." || name.contains('/') || name.contains('\0') || !valid_tag(tag) {
                return Err(Fail::bad("a marker needs a plain file name and a tag"));
            }
            markers.push(Marker { name: name.as_bytes().to_vec(), tag: tag.to_string(), private: m.get("private").and_then(Value::as_bool).unwrap_or(false) });
        }
    }

    let mut exclude = HashSet::new();
    if let Some(Value::Array(ex)) = raw.get("exclude") {
        for e in ex {
            if let Some(s) = e.as_str() {
                exclude.insert(s.as_bytes().to_vec());
            }
        }
    }

    let (mut key, mut roots) = (None, Vec::new());
    if let Some(red) = raw.get("redaction").and_then(Value::as_object) {
        if let Some(k) = red.get("key").and_then(Value::as_str).filter(|k| !k.is_empty()) {
            key = Some(unhex(k).ok_or_else(|| Fail::bad("redaction key must be hex"))?);
        }
        if let Some(Value::Array(rs)) = red.get("roots") {
            for r in rs {
                let hashes: HashSet<String> = r.get("hashes").and_then(Value::as_array).map(|a| a.iter().filter_map(|h| h.as_str().map(str::to_string)).collect()).unwrap_or_default();
                let inodes: HashSet<(u64, u64)> = r
                    .get("inodes")
                    .and_then(Value::as_array)
                    .map(|a| a.iter().filter_map(|p| Some((p.get(0)?.as_u64()?, p.get(1)?.as_u64()?))).collect())
                    .unwrap_or_default();
                if hashes.len() + inodes.len() > MAX_REDACTION {
                    return Err(Fail::bad("too many redactions"));
                }
                roots.push(RedactRoot {
                    root: r.get("root").and_then(Value::as_str).unwrap_or("").to_string(),
                    base: r.get("base").and_then(Value::as_str).unwrap_or("").to_string(),
                    hashes,
                    inodes,
                });
            }
        }
    }
    let names: Vec<String> = markers.iter().map(|m| String::from_utf8_lossy(&m.name).into_owned()).collect();
    let id = policy_id(rules_raw, &names);
    Ok(Policy { exclude, rules, markers, key, redact_roots: roots, id })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn vectors() -> Value {
        serde_json::from_str(include_str!("../../tests/data/rollup_match_vectors.json")).unwrap()
    }

    #[test]
    fn every_agent_match_vector() {
        let v = vectors();
        let mut ran = 0;
        for case in v["match"].as_array().unwrap() {
            if case["agent"].as_bool() != Some(true) {
                continue;
            }
            let rules: Vec<Rule> = case["rules"].as_array().unwrap().iter().map(|r| parse_rule(r).unwrap()).collect();
            let path = case["path"].as_str().unwrap();
            let name = path.rsplit('/').next().unwrap();
            let s = Subject::new(name.as_bytes(), path, case["is_dir"].as_bool().unwrap());
            // first matching rule wins; a keep rule answers no tag
            let got = rules.iter().find(|r| r.matches(&s)).and_then(|r| if r.keep { None } else { r.tag.clone() });
            let want = case["expect"].as_str().map(str::to_string);
            assert_eq!(got, want, "vector {:?}", case["name"]);
            ran += 1;
        }
        assert!(ran >= 40, "ran {ran}");
    }

    #[test]
    fn every_policy_vector() {
        for case in vectors()["policy"].as_array().unwrap() {
            let rules = case["rules"].as_array().unwrap();
            let markers: Vec<String> = case["markers"].as_array().unwrap().iter().map(|m| m.as_str().unwrap().to_string()).collect();
            assert_eq!(policy_id(rules, &markers), case["id"].as_str().unwrap(), "{case}");
        }
    }

    #[test]
    fn every_redaction_vector() {
        let cases = vectors()["redaction"].as_array().unwrap().clone();
        assert!(cases.len() >= 6);
        for case in cases {
            let key = unhex(case["key_hex"].as_str().unwrap()).unwrap();
            let got = redaction_hash(&key, case["root"].as_str().unwrap(), case["rel_path"].as_str().unwrap());
            assert_eq!(got, case["hash"].as_str().unwrap(), "{case}");
        }
    }

    fn m(pattern: &str, path: &str, is_dir: bool, fold: bool) -> bool {
        let name = path.rsplit('/').next().unwrap();
        Pattern::new(pattern, fold).matches(&Subject::new(name.as_bytes(), path, is_dir))
    }

    #[test]
    fn wildcards_stay_inside_a_component() {
        assert!(m("/a/*/c", "/a/b/c", true, false));
        assert!(!m("/a/*/c", "/a/b/x/c", true, false));
        assert!(m("/a/**/c", "/a/c", true, false));
        assert!(m("/a/**/c", "/a/x/y/c", true, false));
        assert!(m("/a/**", "/a/b", true, false));
        assert!(!m("/a/**", "/a", true, false));
        assert!(m("**/AppData/Local/Temp", "/Users/x/AppData/Local/Temp", true, true));
        assert!(m("**/AppData/Local/Temp", "/AppData/Local/Temp", true, true));
        assert!(m("*.tmp", "/x/y.tmp", false, false));
        assert!(!m("*.tmp", "/x/y.tmp2", false, false));
        assert!(m("a?c", "/a\u{e9}c", false, false));
    }

    #[test]
    fn case_folding_is_ascii_only() {
        assert!(m("Node_Modules", "/x/node_modules", true, true));
        assert!(!m("\u{c9}cole", "/x/\u{e9}cole", true, true));
        assert!(!m("Node_Modules", "/x/node_modules", true, false));
    }

    #[test]
    fn bracket_characters_are_literal() {
        assert!(m("[x]", "/a/[x]", true, false));
        assert!(!m("[x]", "/a/x", true, false));
    }

    #[test]
    fn rule_validation() {
        let bad = |v: Value| configure(v.as_object().unwrap()).is_err();
        assert!(bad(json!({"rules": [{"tag": "CACHE", "match": ["x"]}]})));
        assert!(bad(json!({"rules": [{"tag": "[cache]", "match": ["x"]}]})));
        assert!(bad(json!({"rules": [{"match": ["x"]}]})));
        assert!(bad(json!({"rules": [{"tag": "[A]", "match": ["x"], "type": "weird"}]})));
        assert!(!bad(json!({"rules": [{"match": ["x"], "keep": true}]})));
        assert!(bad(json!({"markers": [{"name": "../x", "tag": "[A]"}]})));
        let p = configure(json!({"rules": [{"tag": "[A]", "match": ["x"]}]}).as_object().unwrap()).unwrap();
        assert_eq!(p.id.len(), 12);
    }

    #[test]
    fn limits() {
        let many: Vec<Value> = (0..=MAX_RULES).map(|_| json!({"tag": "[A]", "match": ["x"]})).collect();
        assert!(configure(json!({"rules": many}).as_object().unwrap()).is_err());
        let long = "a".repeat(MAX_PATTERN_BYTES + 1);
        assert!(configure(json!({"rules": [{"tag": "[A]", "match": [long]}]}).as_object().unwrap()).is_err());
    }
}
