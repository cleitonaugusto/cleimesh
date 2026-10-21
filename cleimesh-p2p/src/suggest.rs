//! The smallest permission an agent's receipts show it needed
//! (C5): for each tool its token grants, the
//! directories its calls actually read and wrote, as narrower grants for
//! `cleimesh token derive --grants`. Nothing is applied: a human decides.
//!
//! Result receipts name directories by pseudonym (`fs_dir_pseudonym`); the
//! node's owner maps them back by walking the granted directories. A
//! directory renamed or removed since resolves to its nearest parent that
//! still exists, so a suggestion errs toward granting more, never less.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::{Path, PathBuf};

use cleimesh_aat::{SigningKey, VerifyingKey};
use cleimesh_receipt::{verify_log, Failure, Receipt};
use serde::Serialize;
use serde_json::Value;

use crate::grants::{Grants, ToolGrant};
use crate::report::Lang;
use crate::receipts::{fs_dir_pseudonym, DECISION_ACTION_ID, FS_MAX_DEPTH, RESULT_ACTION_ID};

/// Which calls to learn from.
#[derive(Debug, Clone, Default)]
pub struct Window {
    /// Inclusive bounds, in milliseconds since the epoch.
    pub since_ms: Option<u64>,
    pub until_ms: Option<u64>,
}

/// What the receipts show for one tool, and what to grant it instead.
#[derive(Debug, Clone, Default, Serialize)]
pub struct ToolUse {
    /// Calls that ran in the window.
    pub calls: u64,
    /// Of those, calls whose result receipt says what they touched.
    pub observed: u64,
    pub files_read: u64,
    pub files_written: u64,
    pub refused: u64,
    /// Pseudonyms that no longer resolve (renamed or removed directories).
    pub unresolved: u64,
    pub granted: ToolGrant,
    /// `None`: drop the tool. Equal to `granted` when the receipts don't
    /// allow narrowing it.
    pub suggested: Option<ToolGrant>,
    /// Why the suggestion is what it is.
    pub notes: Vec<Note>,
}

/// Why a tool's suggestion is what it is.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "note", rename_all = "snake_case")]
pub enum Note {
    /// No call in the window: drop the tool.
    NeverCalled,
    /// Some calls were recorded by a version that did not say what they
    /// touched: the grant is kept as it is.
    Unobserved { unobserved: u64, calls: u64 },
    /// Directories renamed or removed since the calls: their parent is
    /// suggested.
    Unresolved { directories: u64 },
    /// The node does not observe network use yet: network is kept.
    NetworkKept,
}

impl Note {
    fn text(&self, lang: Lang) -> String {
        match (self, lang) {
            (Note::NeverCalled, Lang::En) => "never called in the period: drop it from the token".into(),
            (Note::NeverCalled, Lang::Pt) => "nunca chamada no período: retirar do token".into(),
            (Note::Unobserved { unobserved, calls }, Lang::En) => format!(
                "{} of {} calls without a record of what they touched (receipts from a version that did not record it): kept as it is",
                unobserved, calls
            ),
            (Note::Unobserved { unobserved, calls }, Lang::Pt) => format!(
                "{} de {} chamadas sem registro do que tocaram (recibos de uma versão que não registrava isso): mantida como está",
                unobserved, calls
            ),
            (Note::Unresolved { directories }, Lang::En) => {
                format!("{} directory(ies) renamed or removed since the calls: the parent is suggested", directories)
            }
            (Note::Unresolved { directories }, Lang::Pt) => {
                format!("{} pasta(s) renomeada(s) ou apagada(s) desde as chamadas: sugerida a pasta-pai", directories)
            }
            (Note::NetworkKept, Lang::En) => "network: the node does not observe network use yet; kept".into(),
            (Note::NetworkKept, Lang::Pt) => "rede: o nó ainda não observa o uso de rede; mantida".into(),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Suggestion {
    pub lines: usize,
    pub verified: bool,
    #[serde(serialize_with = "failures")]
    pub failures: Vec<Failure>,
    pub holder: String,
    pub calls: u64,
    pub tools: BTreeMap<String, ToolUse>,
}

fn failures<S: serde::Serializer>(f: &[Failure], s: S) -> Result<S::Ok, S::Error> {
    s.collect_seq(f.iter().map(|f| serde_json::json!({"line": f.line, "reason": f.reason})))
}

impl Suggestion {
    /// The grants to derive: the suggested ones of the tools kept.
    pub fn grants(&self) -> Grants {
        self.tools.iter().filter_map(|(t, u)| u.suggested.clone().filter(|g| *g != ToolGrant::default()).map(|g| (t.clone(), g))).collect()
    }

    /// Tools to keep in the derived token.
    pub fn kept_tools(&self) -> Vec<String> {
        self.tools.iter().filter(|(_, u)| u.suggested.is_some()).map(|(t, _)| t.clone()).collect()
    }

    /// Whether the suggestion grants less than the token does.
    pub fn narrows(&self) -> bool {
        self.tools.values().any(|u| u.suggested.as_ref() != Some(&u.granted))
    }
}

/// The directory `pseudonym` names below `grant`, found by walking the
/// disk: as deep as it still resolves, and whether it resolved fully.
pub fn resolve(node_key: &SigningKey, grant: &str, pseudonym: &str) -> (PathBuf, bool) {
    let mut dir = PathBuf::from(grant);
    if pseudonym == "." {
        return (dir, true);
    }
    let wanted: Vec<&str> = pseudonym.split('/').collect();
    let mut components: Vec<String> = Vec::new();
    for depth in 0..wanted.len().min(FS_MAX_DEPTH) {
        let target = wanted[..=depth].join("/");
        let found = std::fs::read_dir(&dir).ok().and_then(|entries| {
            entries.filter_map(|e| e.ok()).filter(|e| e.file_type().is_ok_and(|t| t.is_dir())).find_map(|e| {
                let name = e.file_name().to_string_lossy().into_owned();
                let mut path = components.clone();
                path.push(name.clone());
                (fs_dir_pseudonym(node_key, grant, &path) == target).then_some(name)
            })
        });
        match found {
            Some(name) => {
                dir.push(&name);
                components.push(name);
            }
            None => return (dir, false),
        }
    }
    (dir, true)
}

/// `dirs` without the ones inside another of them.
fn outermost(dirs: BTreeSet<PathBuf>) -> Vec<String> {
    let mut kept: Vec<PathBuf> = Vec::new();
    for dir in dirs {
        if !kept.iter().any(|k| dir.starts_with(k)) {
            kept.retain(|k| !k.starts_with(&dir));
            kept.push(dir);
        }
    }
    kept.into_iter().map(|d| d.to_string_lossy().into_owned()).collect()
}

fn text(v: &Value) -> Option<&str> {
    v.as_str()
}

/// Learns from `log` (verified against `anchor`) what `holder` (the leaf's
/// JWK thumbprint URI) used of `tools` and `granted`, its token's tools and
/// sandbox grants, and suggests the smallest grants that still allow it.
pub fn suggest(log: &[u8], anchor: &VerifyingKey, node_key: &SigningKey, holder: &str, tools: &[String], granted: &Grants, window: &Window) -> Suggestion {
    let check = verify_log(log, anchor);
    let receipts: Vec<Receipt> = String::from_utf8_lossy(log).lines().filter_map(|l| Receipt::parse(l).ok()).collect();

    // Decision step → tool, for this holder's allowed calls in the window.
    let decisions: HashMap<&str, &str> = receipts
        .iter()
        .filter(|r| r.action_id == DECISION_ACTION_ID && r.params["decision"] == "allowed")
        .filter(|r| r.params["authority"]["holder"] == holder)
        .filter(|r| window.since_ms.is_none_or(|t| r.ts_ms >= t) && window.until_ms.is_none_or(|t| r.ts_ms <= t))
        .filter_map(|r| Some((r.step_id.as_str(), text(&r.params["tool"])?)))
        .collect();

    let mut uses: BTreeMap<String, ToolUse> = tools
        .iter()
        .map(|t| (t.clone(), ToolUse { granted: granted.get(t).cloned().unwrap_or_default(), ..Default::default() }))
        .collect();
    let mut seen: BTreeMap<String, (BTreeSet<PathBuf>, BTreeSet<PathBuf>)> = BTreeMap::new();
    let mut calls = 0;
    for result in receipts.iter().filter(|r| r.action_id == RESULT_ACTION_ID) {
        let Some(tool) = text(&result.params["decision_step"]).and_then(|s| decisions.get(s)) else { continue };
        let Some(usage) = uses.get_mut(*tool) else { continue };
        calls += 1;
        usage.calls += 1;
        let Some(fs) = result.params["observed"].get("fs") else { continue };
        usage.observed += 1;
        let (read, write) = seen.entry(tool.to_string()).or_default();
        for g in fs["grants"].as_array().into_iter().flatten() {
            let Some(grant) = text(&g["grant"]) else { continue };
            usage.files_read += g["files_read"].as_u64().unwrap_or(0);
            usage.files_written += g["files_written"].as_u64().unwrap_or(0);
            usage.refused += g["refused"].as_u64().unwrap_or(0);
            for (list, into) in [(&g["read"], &mut *read), (&g["write"], &mut *write)] {
                for pseudonym in list.as_array().into_iter().flatten().filter_map(Value::as_str) {
                    let (dir, exact) = resolve(node_key, grant, pseudonym);
                    usage.unresolved += u64::from(!exact);
                    into.insert(dir);
                }
            }
        }
    }

    for (tool, usage) in uses.iter_mut() {
        let granted = usage.granted.clone();
        if usage.calls == 0 {
            usage.notes.push(Note::NeverCalled);
            continue;
        }
        if usage.observed < usage.calls {
            usage.notes.push(Note::Unobserved { unobserved: usage.calls - usage.observed, calls: usage.calls });
            usage.suggested = Some(granted);
            continue;
        }
        let (read, write) = seen.remove(tool).unwrap_or_default();
        let write = outermost(write);
        let read: Vec<String> = outermost(read).into_iter().filter(|r| !write.iter().any(|w| Path::new(r).starts_with(w))).collect();
        if usage.unresolved > 0 {
            usage.notes.push(Note::Unresolved { directories: usage.unresolved });
        }
        if granted.network {
            usage.notes.push(Note::NetworkKept);
        }
        usage.suggested = Some(ToolGrant { read, write, ..granted });
    }

    Suggestion { lines: check.lines, verified: check.ok(), failures: check.failures, holder: holder.to_string(), calls, tools: uses }
}

fn short(s: &str) -> String {
    let s = s.trim_start_matches("urn:ietf:params:oauth:jwk-thumbprint:sha-256:");
    if s.chars().count() > 16 { format!("{}…", s.chars().take(16).collect::<String>()) } else { s.to_string() }
}

fn dirs(list: &[String], lang: Lang) -> String {
    if list.is_empty() { lang.pick("none", "nenhuma").into() } else { list.join(", ") }
}

/// The suggestion as text, tool by tool: what was granted, what the
/// receipts show, and what to grant instead.
pub fn to_text(s: &Suggestion, lang: Lang) -> String {
    let t = |en, pt| lang.pick(en, pt);
    let mut out = match lang {
        Lang::En => format!("Minimal observed permission, agent {}\n", short(&s.holder)),
        Lang::Pt => format!("Permissão mínima observada, agente {}\n", short(&s.holder)),
    };
    let log = if s.verified { t("verified", "verificado") } else { t("FAILING verification", "COM FALHAS de verificação") };
    out.push_str(&match lang {
        Lang::En => format!("{} call(s) in the period; log {} ({} receipts)\n", s.calls, log, s.lines),
        Lang::Pt => format!("{} chamada(s) no período; log {} ({} recibos)\n", s.calls, log, s.lines),
    });
    if s.calls > 0 && s.calls < 10 {
        out.push_str(t(
            "Warning: few calls; the suggestion may cut what the agent rarely uses.\n",
            "Aviso: poucas chamadas; a sugestão pode cortar o que o agente usa raramente.\n",
        ));
    }
    for (tool, u) in &s.tools {
        out.push_str(&match lang {
            Lang::En => format!("\n{}: {} call(s), {} file(s) read, {} written", tool, u.calls, u.files_read, u.files_written),
            Lang::Pt => format!("\n{}: {} chamada(s), {} arquivo(s) lido(s), {} gravado(s)", tool, u.calls, u.files_read, u.files_written),
        });
        if u.refused > 0 {
            out.push_str(&match lang {
                Lang::En => format!(", {} access(es) refused by the sandbox", u.refused),
                Lang::Pt => format!(", {} acesso(s) recusado(s) pelo sandbox", u.refused),
            });
        }
        out.push('\n');
        match &u.suggested {
            None => {}
            Some(g) => {
                if u.granted.read != g.read || !u.granted.read.is_empty() {
                    out.push_str(&format!("  {}: {} -> {}\n", t("read", "leitura"), dirs(&u.granted.read, lang), dirs(&g.read, lang)));
                }
                if u.granted.write != g.write || !u.granted.write.is_empty() {
                    out.push_str(&format!("  {}: {} -> {}\n", t("write", "escrita"), dirs(&u.granted.write, lang), dirs(&g.write, lang)));
                }
            }
        }
        for note in &u.notes {
            out.push_str(&format!("  {}\n", note.text(lang)));
        }
    }
    out
}
