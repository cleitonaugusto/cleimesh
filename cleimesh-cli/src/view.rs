//! `cleimesh audit view`: the receipt log as one self-contained HTML page.
//!
//! A timeline a person reads in a browser: what each call was, whether it
//! ran, what an untrusted read changed, what was refused and why, with the
//! decision and its result on one row. Static: no script, no external
//! resource, every value escaped (tool names and denials come from servers
//! and agents). The page shows the log; `cleimesh audit verify` vouches for it.

use std::collections::{HashMap, HashSet};

use cleimesh_p2p::receipts::{DECISION_ACTION_ID, RESULT_ACTION_ID, SETTLED_ACTION_ID, TAINT_CLEARED_ACTION_ID};
use cleimesh_receipt::{Failure, Receipt, PRUNE_ACTION_ID};
use serde_json::Value;

/// What the page says about the log's integrity.
pub enum Verification {
    /// Every signature and chain link checked against the node key.
    Verified { signer: String },
    /// Checked, and these lines failed.
    Failed(Vec<Failure>),
    /// Not checked, and why.
    NotChecked(String),
}

pub fn escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(c),
        }
    }
    out
}

const THUMBPRINT: &str = "urn:ietf:params:oauth:jwk-thumbprint:sha-256:";

fn when(ts_ms: u64) -> String {
    chrono::DateTime::from_timestamp_millis(ts_ms as i64).map(|t| t.format("%Y-%m-%d %H:%M:%S").to_string()).unwrap_or_else(|| ts_ms.to_string())
}

fn short_agent(holder: &str) -> String {
    if let Some(session) = holder.strip_prefix("claude-code:session:") {
        return format!("Claude Code session {}", session.chars().take(8).collect::<String>());
    }
    let h = holder.strip_prefix(THUMBPRINT).unwrap_or(holder);
    h.chars().take(10).collect()
}

/// Escaped text with every step id that has a row turned into a link to it.
fn linked(text: &str, rows: &HashSet<String>) -> String {
    // Step ids are hex and dashes; scan for such runs instead of every id.
    let mut out = String::new();
    let mut run = String::new();
    let flush = |run: &mut String, out: &mut String| {
        if rows.contains(run.as_str()) {
            out.push_str(&format!("<a href=\"#r-{run}\">{}</a>", short_step(run)));
        } else {
            out.push_str(&escape(run));
        }
        run.clear();
    };
    for c in text.chars() {
        if c.is_ascii_hexdigit() || c == '-' {
            run.push(c);
        } else {
            flush(&mut run, &mut out);
            out.push_str(&escape(&c.to_string()));
        }
    }
    flush(&mut run, &mut out);
    out
}

fn short_step(id: &str) -> String {
    format!("…{}", id.get(id.len().saturating_sub(6)..).unwrap_or(id))
}

/// A denial as a person reads it: without the "Authorization failed" and
/// "<tool> refused:" prefixes, and with the agent named "this agent".
fn plain_denial(denial: &str, tool: &str) -> String {
    let d = denial.strip_prefix("Authorization failed: ").unwrap_or(denial);
    let d = d.strip_prefix(&format!("{tool} refused: ")).unwrap_or(d);
    let mut d = d.to_string();
    while let Some(start) = d.find("holder ") {
        let rest = &d[start + "holder ".len()..];
        if !rest.starts_with(THUMBPRINT) {
            break;
        }
        let end = rest.find(' ').unwrap_or(rest.len());
        d.replace_range(start..start + "holder ".len() + end, "this agent");
    }
    let d = d.replace("this agent in this chain received", "the agent had received");
    // Clauses joined by "; " read as sentences.
    d.split("; ")
        .map(|c| {
            let mut ch = c.chars();
            match ch.next() {
                Some(f) => f.to_uppercase().chain(ch).collect::<String>(),
                None => String::new(),
            }
        })
        .collect::<Vec<_>>()
        .join(". ")
        + "."
}

struct Row {
    step: String,
    line: usize,
    /// Every log line shown in this row (a call, its result, settlements).
    lines: Vec<usize>,
    ts_ms: u64,
    badge: (&'static str, &'static str),
    title: String,
    text: String,
    details: Vec<(&'static str, String)>,
    raw: Vec<String>,
}

pub fn render(lines: &[String], source: &str, verification: &Verification, generated_ms: u64) -> String {
    let parsed: Vec<Option<Receipt>> = lines.iter().map(|l| Receipt::parse(l).ok()).collect();
    let failed: HashMap<usize, String> = match verification {
        Verification::Failed(f) => f.iter().map(|f| (f.line, f.reason.clone())).collect(),
        _ => HashMap::new(),
    };
    // Results and settlements attach to the call they belong to.
    let mut result_of: HashMap<String, usize> = HashMap::new();
    let mut settlements_of: HashMap<String, Vec<usize>> = HashMap::new();
    let mut decided: HashSet<String> = HashSet::new();
    for (i, r) in parsed.iter().enumerate() {
        let Some(r) = r else { continue };
        if r.action_id == DECISION_ACTION_ID {
            decided.insert(r.step_id.clone());
        } else if r.action_id == RESULT_ACTION_ID {
            if let Some(d) = r.params["decision_step"].as_str() {
                result_of.insert(d.to_string(), i);
            }
        } else if r.action_id == SETTLED_ACTION_ID {
            if let Some(s) = r.params["settles"].as_str() {
                settlements_of.entry(s.to_string()).or_default().push(i);
            }
        }
    }
    // A result shows inside its call's row, and its settlements with it.
    let mut attached: HashSet<usize> = result_of.iter().filter(|(d, _)| decided.contains(*d)).map(|(_, i)| *i).collect();
    let attached_results: Vec<String> = attached.iter().filter_map(|i| parsed[*i].as_ref().map(|r| r.step_id.clone())).collect();
    for step in attached_results {
        attached.extend(settlements_of.get(&step).into_iter().flatten().copied());
    }
    // Every step id a link can point to: rows, and the results inside them.
    let mut anchors: HashSet<String> = HashSet::new();
    for r in parsed.iter().flatten() {
        anchors.insert(r.step_id.clone());
    }

    let (mut calls, mut allowed, mut refused, mut reads, mut unknown) = (0, 0, 0, 0, 0);
    let mut rows = Vec::new();
    for (i, r) in parsed.iter().enumerate() {
        let n = i + 1;
        let Some(r) = r else {
            rows.push(Row { step: format!("line-{n}"), line: n, lines: vec![n], ts_ms: 0, badge: ("bad", "UNREADABLE"), title: "unreadable line".into(), text: String::new(), details: vec![], raw: vec![lines[i].clone()] });
            continue;
        };
        if attached.contains(&i) {
            continue;
        }
        let p = &r.params;
        let s = |v: &Value| v.as_str().unwrap_or("").to_string();
        let mut row = Row { step: r.step_id.clone(), line: n, lines: vec![n], ts_ms: r.ts_ms, badge: ("info", ""), title: String::new(), text: String::new(), details: vec![("receipt", r.step_id.clone())], raw: vec![lines[i].clone()] };
        if r.action_id == DECISION_ACTION_ID {
            calls += 1;
            let tool = s(&p["tool"]);
            row.title = tool.clone();
            row.details.push(("caller", s(&p["caller"])));
            row.details.push(("input sha256", s(&p["input_sha256"])));
            let a = &p["authority"];
            if let Some(h) = a["holder"].as_str() {
                row.details.push(("agent", short_agent(h)));
                row.details.push(("delegation depth", a["depth"].to_string()));
            }
            if let Some(d) = p["sandbox"]["tool_definition_sha256"].as_str() {
                row.details.push(("tool definition sha256", d.to_string()));
            }
            if p["decision"] == "denied" {
                refused += 1;
                row.badge = ("refused", "REFUSED");
                row.text = linked(&plain_denial(&s(&p["denial"]), &tool), &anchors);
            } else {
                allowed += 1;
                if a["taints"] == true {
                    reads += 1;
                    row.badge = ("read", "UNTRUSTED READ");
                    let from = p["source"].as_str().map(|s| format!(" ({})", escape(s))).unwrap_or_default();
                    row.text = if a["kind"] == "guard" {
                        format!("Brought in outside content{from}. From here on, this session runs only listed commands, reads no secrets and writes nothing outside the project, until a person clears it.")
                    } else {
                        format!("Brought in content from outside{from}. From here on, this agent's actions marked clean-only are refused, or limited to what the token fixes, until a person clears it.")
                    };
                } else if let Some(t) = a["tainted_by"].as_str() {
                    row.badge = ("allowed", "ALLOWED");
                    row.text = if a["kind"] == "guard" {
                        format!("Allowed after the untrusted read {}: it is among what a session may still do after outside content.", linked(t, &anchors))
                    } else {
                        format!("Allowed after the untrusted read {}, inside the limits the token fixes for a tainted agent.", linked(t, &anchors))
                    };
                } else {
                    row.badge = ("allowed", "ALLOWED");
                    row.text = if a["clean_only"] == true { "Allowed: an action, and this agent had read nothing untrusted.".into() } else { "Allowed.".into() };
                }
                if let Some(ri) = result_of.get(&r.step_id) {
                    if let Some(res) = &parsed[*ri] {
                        let o = &res.params["observed"];
                        row.raw.push(lines[*ri].clone());
                        row.lines.push(ri + 1);
                        row.details.push(("result receipt", res.step_id.clone()));
                        if let Some(h) = o["output_sha256"].as_str() {
                            row.details.push(("output sha256", h.to_string()));
                        }
                        if o["outcome"] == "unknown" {
                            let settled = settlements_of.get(&res.step_id).cloned().unwrap_or_default();
                            if settled.is_empty() {
                                unknown += 1;
                                row.badge = ("unknown", "OUTCOME UNKNOWN");
                            }
                            row.text.push_str(&format!(" Cut at its time limit ({} ms): whether it took effect is unknown, and the same call is refused until a person settles it.", o["timed_out_after_ms"].as_u64().map(|v| v.to_string()).unwrap_or_else(|| "?".into())));
                            for (k, si) in settled.iter().enumerate() {
                                if let Some(st) = &parsed[*si] {
                                    let sp = &st.params;
                                    row.raw.push(lines[*si].clone());
                                    row.lines.push(si + 1);
                                    let verb = if sp["supersedes"].is_string() { "Corrected" } else { "Settled" };
                                    row.text.push_str(&format!(
                                        " <b>{verb}: {}</b> by {} on {}: {}{}.",
                                        escape(&s(&sp["outcome"])),
                                        escape(&s(&sp["settled_by"]).if_empty("unnamed")),
                                        when(st.ts_ms),
                                        escape(&s(&sp["evidence"])),
                                        sp["evidence_sha256"].as_str().map(|d| format!(" (checked against {}, sha256 {}…)", escape(&s(&sp["evidence_name"]).if_empty("a document")), escape(&d.chars().take(16).collect::<String>()))).unwrap_or_default()
                                    ));
                                    if k == settled.len() - 1 {
                                        row.badge = if sp["outcome"] == "succeeded" { ("allowed", "SETTLED: RAN") } else { ("refused", "SETTLED: DID NOT RUN") };
                                    }
                                }
                            }
                        } else if o["success"] == false || !res.success {
                            row.text.push_str(" It ran and failed.");
                        } else if let Some(ms) = o["duration_ms"].as_u64() {
                            row.text.push_str(&format!(" Ran in {ms} ms."));
                        }
                    }
                } else if a["kind"] == "guard" {
                    row.text.push_str(" Passed on to Claude Code, whose own permissions still apply.");
                } else {
                    row.text.push_str(" No result recorded yet.");
                }
            }
        } else if r.action_id == RESULT_ACTION_ID {
            row.title = s(&p["tool"]);
            row.badge = ("info", "RESULT");
            row.text = format!("Result of {} (its decision is not in this log).", linked(&s(&p["decision_step"]), &anchors));
        } else if r.action_id == SETTLED_ACTION_ID {
            row.title = "settlement".into();
            row.badge = ("info", "SETTLED");
            row.text = format!("{} settled {} as {}: {}", escape(&s(&p["settled_by"]).if_empty("Someone")), linked(&s(&p["settles"]), &anchors), escape(&s(&p["outcome"])), escape(&s(&p["evidence"])));
        } else if r.action_id == TAINT_CLEARED_ACTION_ID {
            row.title = "taint cleared".into();
            row.badge = ("cleared", "CLEARED BY A PERSON");
            row.text = format!("Agent {} may use its actions again. Reason: {}", escape(&short_agent(&s(&p["holder"]))), escape(&s(&p["reason"])));
        } else if r.action_id == PRUNE_ACTION_ID {
            row.title = "retention".into();
            row.badge = ("info", "PRUNED");
            row.text = format!("{} older receipt(s) removed under the retention policy, and this receipt records it.", p["removed_lines"]);
        } else {
            row.title = r.action_id.clone();
            row.badge = ("info", "OTHER");
            row.text = escape(&r.action_id);
        }
        rows.push(row);
    }

    let mut html = String::new();
    html.push_str("<!doctype html>\n<html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\n");
    html.push_str("<meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; style-src 'unsafe-inline'\">\n");
    html.push_str(&format!("<title>CleiMesh receipts: {}</title>\n<style>{}</style></head><body>\n", escape(source), CSS));
    html.push_str("<header><h1>What your agents did</h1>");
    html.push_str(&format!("<p class=\"src\">{} · {} receipt(s)</p>", escape(source), lines.len()));
    match verification {
        Verification::Verified { signer } => html.push_str(&format!(
            "<div class=\"seal ok\"><b>Verified.</b> Every signature and hash-chain link checks against the node key <code>{}</code>. Lines cut from the end are caught only against a saved head: <code>cleimesh audit verify --head</code>.</div>",
            escape(signer)
        )),
        Verification::Failed(f) => html.push_str(&format!(
            "<div class=\"seal bad\"><b>Verification failed on {} line(s).</b> The log was changed, reordered or cut, or is signed by another key; the rows marked below are not to be trusted.</div>",
            f.len()
        )),
        Verification::NotChecked(why) => html.push_str(&format!("<div class=\"seal none\"><b>Not verified.</b> {}</div>", escape(why))),
    }
    html.push_str(&format!(
        "<ul class=\"stats\"><li><b>{calls}</b> calls</li><li><b>{allowed}</b> allowed</li><li class=\"s-refused\"><b>{refused}</b> refused</li><li class=\"s-read\"><b>{reads}</b> untrusted reads</li><li class=\"s-unknown\"><b>{unknown}</b> outcome unknown</li></ul></header>\n<main>\n"
    ));
    for row in &rows {
        let bad: Vec<String> = row.lines.iter().filter_map(|l| failed.get(l).map(|why| format!("line {l}: {why}"))).collect();
        html.push_str(&format!("<article id=\"r-{}\" class=\"row {}{}\">", escape(&row.step), row.badge.0, if bad.is_empty() { "" } else { " tampered" }));
        html.push_str(&format!("<div class=\"when\">{}<span>line {}</span></div>", if row.ts_ms > 0 { when(row.ts_ms) } else { String::new() }, row.line));
        html.push_str(&format!("<div class=\"what\"><span class=\"badge\">{}</span> <b class=\"tool\">{}</b><p>{}</p>", row.badge.1, escape(&row.title), row.text));
        for reason in &bad {
            html.push_str(&format!("<p class=\"fail\">Fails verification, {}</p>", escape(reason)));
        }
        html.push_str("<details><summary>Receipt details</summary><dl>");
        for (k, v) in &row.details {
            html.push_str(&format!("<dt>{}</dt><dd><code>{}</code></dd>", k, escape(v)));
        }
        html.push_str("</dl>");
        for raw in &row.raw {
            html.push_str(&format!("<pre>{}</pre>", escape(raw)));
        }
        html.push_str("</details></div></article>\n");
    }
    if rows.is_empty() {
        html.push_str("<p class=\"empty\">No receipts yet.</p>");
    }
    html.push_str(&format!(
        "</main><footer>Generated by <code>cleimesh audit view</code> on {} UTC. Receipts keep digests, never the data a call touched. This page shows the log; <code>cleimesh audit verify</code> is what vouches for it, and any receipt can be proven to a third party with <code>cleimesh audit prove</code>.</footer></body></html>\n",
        when(generated_ms)
    ));
    html
}

trait IfEmpty {
    fn if_empty(self, other: &str) -> String;
}

impl IfEmpty for String {
    fn if_empty(self, other: &str) -> String {
        if self.is_empty() { other.to_string() } else { self }
    }
}

const CSS: &str = r#"
:root{--bg:#fafaf8;--fg:#1b1b1a;--mut:#6b6b66;--line:#e4e3de;--card:#fff;--ok:#1f7a4d;--okbg:#e7f4ec;--bad:#b42318;--badbg:#fdecea;--read:#9a5b00;--readbg:#fff4e0;--unk:#5b4bb7;--unkbg:#efecfb;--clr:#1d5fa8;--clrbg:#e8f0fb}
@media (prefers-color-scheme:dark){:root{--bg:#141413;--fg:#ecebe6;--mut:#9b9a94;--line:#2c2b28;--card:#1c1c1a;--ok:#5cc28c;--okbg:#16281e;--bad:#f07a6e;--badbg:#2f1714;--read:#f0b257;--readbg:#2d2210;--unk:#a89cf0;--unkbg:#211d36;--clr:#7fb0ee;--clrbg:#14223a}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif}
header,main,footer{max-width:960px;margin:0 auto;padding:0 20px}header{padding-top:28px}h1{font-size:24px;margin:0 0 4px}
.src{color:var(--mut);margin:0 0 16px;word-break:break-all}code,pre{font:12.5px/1.45 ui-monospace,SFMono-Regular,Menlo,monospace}
.seal{border-radius:8px;padding:12px 14px;margin-bottom:16px}.seal.ok{background:var(--okbg);color:var(--ok)}.seal.bad{background:var(--badbg);color:var(--bad)}.seal.none{background:var(--line)}
.stats{display:flex;flex-wrap:wrap;gap:8px;list-style:none;padding:0;margin:0 0 20px}.stats li{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:6px 12px}
.stats b{font-size:18px;margin-right:4px}.s-refused b{color:var(--bad)}.s-read b{color:var(--read)}.s-unknown b{color:var(--unk)}
.row{display:grid;grid-template-columns:150px 1fr;gap:14px;background:var(--card);border:1px solid var(--line);border-left:4px solid var(--line);border-radius:8px;padding:12px 14px;margin-bottom:10px}
.row:target{outline:2px solid var(--clr)}.when{color:var(--mut);font-size:13px}.when span{display:block;font-size:12px}
.what p{margin:6px 0 0}.tool{font-family:ui-monospace,Menlo,monospace}.badge{font-size:11px;font-weight:700;letter-spacing:.04em;border-radius:4px;padding:2px 6px;background:var(--line)}
.allowed{border-left-color:var(--ok)}.allowed .badge{background:var(--okbg);color:var(--ok)}.refused{border-left-color:var(--bad)}.refused .badge{background:var(--badbg);color:var(--bad)}
.read{border-left-color:var(--read)}.read .badge{background:var(--readbg);color:var(--read)}.unknown{border-left-color:var(--unk)}.unknown .badge{background:var(--unkbg);color:var(--unk)}
.cleared{border-left-color:var(--clr)}.cleared .badge{background:var(--clrbg);color:var(--clr)}.bad .badge{background:var(--badbg);color:var(--bad)}
.tampered{background:var(--badbg)}.fail{color:var(--bad);font-weight:600}a{color:var(--clr)}
details{margin-top:8px}summary{cursor:pointer;color:var(--mut);font-size:13px}dl{display:grid;grid-template-columns:max-content 1fr;gap:2px 12px;margin:8px 0}dt{color:var(--mut);font-size:13px}dd{margin:0;word-break:break-all}
pre{white-space:pre-wrap;word-break:break-all;background:var(--bg);border:1px solid var(--line);border-radius:6px;padding:8px;max-height:220px;overflow:auto}
footer{color:var(--mut);font-size:13px;padding:16px 20px 40px}.empty{color:var(--mut)}
@media (max-width:640px){.row{grid-template-columns:1fr;gap:4px}}
"#;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escapes_markup_from_servers() {
        assert_eq!(escape("<script>alert('x')</script>&\""), "&lt;script&gt;alert(&#39;x&#39;)&lt;/script&gt;&amp;&quot;");
    }

    #[test]
    fn a_denial_reads_plainly() {
        let d = format!("Authorization failed: send refused: holder {THUMBPRINT}abc in this chain received untrusted content (receipt 01a2)");
        assert_eq!(plain_denial(&d, "send"), "The agent had received untrusted content (receipt 01a2).");
        assert_eq!(plain_denial("send refused: a; b", "send"), "A. B.");
    }

    #[test]
    fn step_ids_with_a_row_become_links_and_nothing_else_does() {
        let rows: HashSet<String> = ["01a2-ff".to_string()].into();
        assert_eq!(linked("see 01a2-ff and 01a2-00 <b>", &rows), "see <a href=\"#r-01a2-ff\">…1a2-ff</a> and 01a2-00 &lt;b&gt;");
    }

    #[test]
    fn an_unreadable_line_is_shown_not_dropped() {
        let html = render(&["<not json>".to_string()], "r.jsonl", &Verification::NotChecked("no key".into()), 0);
        assert!(html.contains("UNREADABLE") && html.contains("&lt;not json&gt;") && !html.contains("<not json>"));
    }
}
