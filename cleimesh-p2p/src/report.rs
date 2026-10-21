//! Privacy reports from a receipt log (C3): which agents, under which
//! delegation and grants, handled a data subject's data (GDPR art. 15,
//! LGPD art. 18), and the record of an agent's operations (GDPR art. 30,
//! LGPD art. 37), in English or Portuguese.
//!
//! The log is verified first, and a report built from a log that fails is
//! marked as such: the CLI refuses to print it unless asked. Reports carry
//! what receipts carry: pseudonyms and digests, never content.

use cleimesh_receipt::{verify_log, Failure, Receipt};
use cleimesh_aat::VerifyingKey;
use serde::Serialize;
use serde_json::Value;

use crate::receipts::{DECISION_ACTION_ID, RESULT_ACTION_ID};

/// The language of the human-readable reports. JSON is the same in both.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Lang {
    #[default]
    En,
    Pt,
}

impl Lang {
    /// `en` or `pt`.
    pub fn parse(s: &str) -> Option<Lang> {
        match s {
            "en" => Some(Lang::En),
            "pt" | "pt-BR" | "pt_BR" => Some(Lang::Pt),
            _ => None,
        }
    }

    /// The English text or the Portuguese one.
    pub fn pick<'a>(self, en: &'a str, pt: &'a str) -> &'a str {
        match self {
            Lang::En => en,
            Lang::Pt => pt,
        }
    }
}

/// Which operations to report. Every set field must match.
#[derive(Debug, Clone, Default, Serialize)]
pub struct Filter {
    /// From `receipts::subject_pseudonym`.
    pub data_subject: Option<String>,
    /// The leaf holder's JWK thumbprint URI, or the caller as receipts name it.
    pub agent: Option<String>,
    /// Inclusive bounds, in milliseconds since the epoch.
    pub since_ms: Option<u64>,
    pub until_ms: Option<u64>,
}

/// What a decision receipt and its result receipt say about one call.
#[derive(Debug, Clone, Serialize)]
pub struct Operation {
    pub ts_ms: u64,
    pub step_id: String,
    pub tool: String,
    pub caller: String,
    pub decision: String,
    pub denial: Option<String>,
    pub data_subject: Option<String>,
    pub purpose: Option<String>,
    /// Kind of authority (`aat`, `capability`, `public_tool`).
    pub authority: Option<String>,
    pub holder: Option<String>,
    pub root_issuer: Option<String>,
    pub delegation_depth: Option<u64>,
    /// What the sandbox granted: readable and writable directories, network.
    pub read: Vec<String>,
    pub write: Vec<String>,
    pub network: Option<bool>,
    /// `None` if denied, or if the result receipt is missing (the call was
    /// cut short, or the log ends before it).
    pub succeeded: Option<bool>,
}

/// A retention run that opened this log (`cleimesh audit prune`).
#[derive(Debug, Clone, Serialize)]
pub struct Pruned {
    pub ts_ms: u64,
    pub removed: u64,
    pub removed_before_ms: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct Report {
    pub lines: usize,
    pub pruned: Option<Pruned>,
    pub verified: bool,
    #[serde(serialize_with = "failures")]
    pub failures: Vec<Failure>,
    pub filter: Filter,
    pub operations: Vec<Operation>,
}

fn failures<S: serde::Serializer>(f: &[Failure], s: S) -> Result<S::Ok, S::Error> {
    s.collect_seq(f.iter().map(|f| serde_json::json!({"line": f.line, "reason": f.reason})))
}

fn text(v: &Value) -> Option<String> {
    v.as_str().map(str::to_string)
}

fn dirs(v: &Value) -> Vec<String> {
    v.as_array().map(|a| a.iter().filter_map(text).collect()).unwrap_or_default()
}

/// Verifies `log` against `anchor` and gathers the operations `filter`
/// selects, oldest first.
pub fn build(log: &[u8], anchor: &VerifyingKey, filter: &Filter) -> Report {
    let check = verify_log(log, anchor);
    let receipts: Vec<Receipt> = String::from_utf8_lossy(log).lines().filter_map(|l| Receipt::parse(l).ok()).collect();
    let results: std::collections::HashMap<String, bool> = receipts
        .iter()
        .filter(|r| r.action_id == RESULT_ACTION_ID)
        .filter_map(|r| Some((text(&r.params["decision_step"])?, r.success)))
        .collect();

    let operations = receipts
        .iter()
        .filter(|r| r.action_id == DECISION_ACTION_ID)
        .map(|r| {
            let p = &r.params;
            let a = &p["authority"];
            let allowed = p["decision"] == "allowed";
            let sandbox = &p["sandbox"];
            let mut read = dirs(&sandbox["allowed_paths"]);
            if sandbox["allow_filesystem_read"] != true {
                read.clear();
            }
            Operation {
                ts_ms: r.ts_ms,
                step_id: r.step_id.clone(),
                tool: text(&p["tool"]).unwrap_or_default(),
                caller: text(&p["caller"]).unwrap_or_default(),
                decision: text(&p["decision"]).unwrap_or_default(),
                denial: text(&p["denial"]),
                data_subject: text(&p["data_subject"]),
                purpose: text(&p["purpose"]),
                authority: text(&a["kind"]),
                holder: text(&a["holder"]),
                root_issuer: text(&a["root_iss"]),
                delegation_depth: a["depth"].as_u64(),
                read,
                write: dirs(&sandbox["writable_paths"]),
                network: sandbox["allow_network"].as_bool(),
                succeeded: if allowed { results.get(&r.step_id).copied() } else { None },
            }
        })
        .filter(|o| filter.data_subject.as_ref().is_none_or(|s| o.data_subject.as_ref() == Some(s)))
        .filter(|o| filter.agent.as_ref().is_none_or(|a| o.holder.as_ref() == Some(a) || &o.caller == a))
        .filter(|o| filter.since_ms.is_none_or(|t| o.ts_ms >= t))
        .filter(|o| filter.until_ms.is_none_or(|t| o.ts_ms <= t))
        .collect();

    let pruned = receipts.first().filter(|r| r.action_id == cleimesh_receipt::PRUNE_ACTION_ID).map(|r| Pruned {
        ts_ms: r.ts_ms,
        removed: r.params["removed_lines"].as_u64().unwrap_or(0),
        removed_before_ms: r.params["removed_before_ms"].as_u64().unwrap_or(0),
    });
    Report { lines: check.lines, pruned, verified: check.ok(), failures: check.failures, filter: filter.clone(), operations }
}

fn utc(ms: u64) -> String {
    chrono::DateTime::from_timestamp_millis(ms as i64).map(|t| t.format("%Y-%m-%d %H:%M:%S UTC").to_string()).unwrap_or_else(|| ms.to_string())
}

fn short(s: &str) -> String {
    let s = s.trim_start_matches("urn:ietf:params:oauth:jwk-thumbprint:sha-256:").trim_start_matches("hmac-sha256:");
    if s.chars().count() > 16 { format!("{}…", s.chars().take(16).collect::<String>()) } else { s.to_string() }
}

/// The report in Portuguese Markdown. `subject_label` and `agent_label` name
/// what was asked for (e.g. the pseudonym, a PeerId).
pub fn to_markdown(report: &Report, signer: &str, subject_label: Option<&str>, agent_label: Option<&str>, lang: Lang) -> String {
    let t = |en, pt| lang.pick(en, pt);
    let mut out = String::new();
    let title = match (subject_label, agent_label) {
        (Some(_), _) => t("Processing report for a data subject", "Relatório de tratamento por titular"),
        (None, Some(_)) => t(
            "Record of an agent's processing operations (GDPR art. 30, LGPD art. 37)",
            "Registro das operações de tratamento do agente (LGPD, art. 37)",
        ),
        _ => t("Report of processing operations", "Relatório de operações de tratamento"),
    };
    out.push_str(&format!("# {}\n\n", title));
    if !report.verified {
        out.push_str(t(
            "> ⚠️ **The receipt log did NOT pass verification.** The data below may have been altered:\n",
            "> ⚠️ **O log de recibos NÃO passou na verificação.** Os dados abaixo podem ter sido alterados:\n",
        ));
        for f in &report.failures {
            out.push_str(&format!("> - {} {}: {}\n", t("line", "linha"), f.line, f.reason));
        }
        out.push('\n');
    }
    if let Some(s) = subject_label {
        out.push_str(&format!("- **{}:** `{}`\n", t("Data subject (pseudonym)", "Titular (pseudônimo)"), s));
    }
    if let Some(a) = agent_label {
        out.push_str(&format!("- **{}:** `{}`\n", t("Agent", "Agente"), a));
    }
    let period = match (report.filter.since_ms, report.filter.until_ms) {
        (None, None) => t("the whole log", "todo o log").to_string(),
        (s, u) => format!(
            "{} {} {}",
            s.map(utc).unwrap_or_else(|| t("start", "início").into()),
            t("to", "a"),
            u.map(utc).unwrap_or_else(|| t("now", "agora").into())
        ),
    };
    out.push_str(&format!("- **{}:** {}\n", t("Period", "Período"), period));
    out.push_str(&format!("- **{}:** `{}`\n", t("Node that signed the receipts", "Nó que assinou os recibos"), signer));
    out.push_str(&format!(
        "- **{}:** {} ({} {})\n",
        t("Log verification", "Verificação do log"),
        if report.verified {
            t("intact: signatures and chaining checked", "íntegro: assinaturas e encadeamento conferidos")
        } else {
            t("FAILED", "FALHOU")
        },
        report.lines,
        t("receipts", "recibos")
    ));
    if let Some(p) = &report.pruned {
        out.push_str(&match lang {
            Lang::En => format!(
                "- **Retention:** on {} {} receipt(s) before {} were removed (the receipt of the removal opens the log)\n",
                utc(p.ts_ms),
                p.removed,
                utc(p.removed_before_ms)
            ),
            Lang::Pt => format!(
                "- **Retenção:** em {} foram eliminados {} recibo(s) anteriores a {} (o recibo da eliminação abre o log)\n",
                utc(p.ts_ms),
                p.removed,
                utc(p.removed_before_ms)
            ),
        });
    }
    out.push('\n');

    let ops = &report.operations;
    let allowed = ops.iter().filter(|o| o.decision == "allowed").count();
    let failed = ops.iter().filter(|o| o.succeeded == Some(false)).count();
    let mut agents: Vec<String> = ops.iter().map(|o| o.holder.clone().unwrap_or_else(|| o.caller.clone())).collect();
    agents.sort();
    agents.dedup();
    let mut purposes: Vec<String> = ops.iter().filter_map(|o| o.purpose.clone()).collect();
    purposes.sort();
    purposes.dedup();
    out.push_str(&format!("## {}\n\n", t("Summary", "Resumo")));
    out.push_str(&match lang {
        Lang::En => format!(
            "- Operations: {} ({} allowed, {} denied; {} of the allowed failed to run)\n",
            ops.len(),
            allowed,
            ops.len() - allowed,
            failed
        ),
        Lang::Pt => format!(
            "- Operações: {} ({} permitidas, {} negadas; {} das permitidas falharam ao executar)\n",
            ops.len(),
            allowed,
            ops.len() - allowed,
            failed
        ),
    });
    out.push_str(&format!("- {}: {}\n", t("Distinct agents", "Agentes distintos"), agents.len()));
    out.push_str(&format!(
        "- {}: {}\n\n",
        t("Declared purposes", "Finalidades declaradas"),
        if purposes.is_empty() { t("none", "nenhuma").to_string() } else { purposes.join("; ") }
    ));

    out.push_str(&format!("## {}\n\n", t("Operations", "Operações")));
    if ops.is_empty() {
        out.push_str(t("No operation found.\n\n", "Nenhuma operação encontrada.\n\n"));
    } else {
        out.push_str(t(
            "| When | Agent | Delegation | Tool | Purpose | Decision | Access granted | Receipt |\n|---|---|---|---|---|---|---|---|\n",
            "| Quando | Agente | Delegação | Tool | Finalidade | Decisão | Acesso concedido | Recibo |\n|---|---|---|---|---|---|---|---|\n",
        ));
        for o in ops {
            let agent = o.holder.as_deref().map(short).unwrap_or_else(|| short(&o.caller));
            let delegation = match (&o.authority, o.delegation_depth) {
                (Some(k), Some(d)) if k == "aat" => format!(
                    "AAT, {} {} {}",
                    d,
                    t("link(s) below", "elo(s) abaixo de"),
                    o.root_issuer.as_deref().map(short).unwrap_or_default()
                ),
                (Some(k), _) => k.clone(),
                (None, _) => "—".into(),
            };
            let decision = match (o.decision.as_str(), o.succeeded) {
                ("allowed", Some(true)) => t("allowed, ran", "permitida, executou").to_string(),
                ("allowed", Some(false)) => t("allowed, failed", "permitida, falhou").to_string(),
                ("allowed", None) => t("allowed, no result receipt", "permitida, sem recibo de resultado").to_string(),
                _ => format!("{}: {}", t("denied", "negada"), o.denial.as_deref().unwrap_or("")),
            };
            let mut access = Vec::new();
            if !o.read.is_empty() {
                access.push(format!("{}: {}", t("read", "leitura"), o.read.join(", ")));
            }
            if !o.write.is_empty() {
                access.push(format!("{}: {}", t("write", "escrita"), o.write.join(", ")));
            }
            if o.network == Some(true) {
                access.push(t("network", "rede").into());
            }
            let access = if o.decision != "allowed" {
                "—".to_string()
            } else if access.is_empty() {
                t("no files, no network", "nenhum arquivo, sem rede").into()
            } else {
                access.join("; ")
            };
            out.push_str(&format!(
                "| {} | `{}` | {} | {} | {} | {} | {} | `{}` |\n",
                utc(o.ts_ms),
                agent,
                delegation,
                o.tool,
                o.purpose.as_deref().unwrap_or("—"),
                decision.replace('|', "\\|"),
                access.replace('|', "\\|"),
                short(&o.step_id)
            ));
        }
        out.push('\n');
    }
    out.push_str("---\n\n");
    out.push_str(t(
        "Generated by CleiMesh from signed receipts (draft-sahu-agent-action-receipts format). \
         The receipts keep pseudonyms and hashes, never the processed content. Each line can be checked with `cleimesh audit verify`. \
         This report describes recorded operations; it is not legal advice.\n",
        "Gerado pelo CleiMesh a partir de recibos assinados (formato draft-sahu-agent-action-receipts). \
         Os recibos guardam pseudônimos e hashes, nunca o conteúdo tratado. Cada linha pode ser conferida com `cleimesh audit verify`. \
         Este relatório descreve operações registradas; não é parecer jurídico.\n",
    ));
    out
}
