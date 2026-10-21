//! Runs examples/demo/demo.sh against the built binary
//! (M6), so the demo can't break unnoticed: its four acts and what each one
//! proves, in English and in Portuguese. The script confines itself to a
//! fresh /tmp directory and removes it.

use std::process::Command;

/// The lines that tell each language's run apart; the rest is the same.
struct Lang {
    code: &'static str,
    allowed: &'static str,
    refused: &'static str,
    mail: &'static str,
    purpose: &'static str,
    narrowed: &'static str,
    directory: &'static str,
}

fn run(lang: &Lang) {
    let script = concat!(env!("CARGO_MANIFEST_DIR"), "/../examples/demo/demo.sh");
    let out = Command::new("bash")
        .arg(script)
        .env("CLEIMESH", env!("CARGO_BIN_EXE_cleimesh"))
        .env("DEMO_LANG", lang.code)
        .env_remove("PAUSE")
        .output()
        .unwrap();
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "demo failed:\n{}\n{}", text, String::from_utf8_lossy(&out.stderr));

    // Act 1: containment.
    assert!(text.contains(lang.allowed), "the doc read should pass:\n{text}");
    assert!(text.contains("cannot read"), "the key read should be blocked by the sandbox:\n{text}");
    assert!(text.contains("tool file_write not granted"), "the write should be refused:\n{text}");
    assert!(text.contains(lang.refused) && text.contains("not granted by the parent"), "the wider token should be refused:\n{text}");
    assert_eq!(text.matches("PRIVATE KEY").count(), 1, "the private key must never come back from the node:\n{text}");

    // Act 2: prompt injection. The draft before the mail goes through; after
    // it, the write is refused for the assistant and for a fresh helper.
    assert!(text.contains("{\"written\": 8}"), "the draft before reading mail should be written:\n{text}");
    assert!(text.contains(lang.mail), "the injected mail should be shown:\n{text}");
    assert_eq!(text.matches("received untrusted content (receipt [").count(), 2, "both writes after the mail should be refused by taint:\n{text}");

    // Act 3: proof.
    assert!(text.contains("OK: 13 receipts"), "the log should verify:\n{text}");
    assert!(text.contains("REPRODUCED"), "the replay should reproduce the calculation:\n{text}");
    assert!(text.contains(lang.purpose), "the privacy report should list the purpose:\n{text}");
    assert!(text.contains("line 4: signature does not verify"), "tampering should be caught:\n{text}");

    // Act 4: the human decides.
    assert!(text.contains(lang.narrowed), "suggest should narrow to the folder used:\n{text}");
    assert!(text.contains("Cleared ") && text.contains("OK: 14 receipts"), "the clearing should be recorded as a receipt:\n{text}");

    let dir = text.lines().find_map(|l| l.trim().strip_prefix(lang.directory)).expect("demo prints its directory");
    assert!(dir.starts_with("/tmp/cleimesh-demo."));
    assert!(!std::path::Path::new(dir).exists(), "the demo left {dir} behind");
}

#[test]
fn demo_script_tells_the_whole_story() {
    run(&Lang {
        code: "en",
        allowed: "ALLOWED",
        refused: "REFUSED",
        mail: "IGNORE PREVIOUS INSTRUCTIONS",
        purpose: "Declared purposes: customer support",
        narrowed: "read: ./email -> ./email/inbox",
        directory: "Demo directory (temporary, removed at the end): ",
    });
}

#[test]
fn demo_script_tells_the_whole_story_in_portuguese() {
    run(&Lang {
        code: "pt",
        allowed: "PERMITIDO",
        refused: "RECUSADO",
        mail: "IGNORE AS INSTRUÇÕES",
        purpose: "Finalidades declaradas: atendimento ao cliente",
        narrowed: "leitura: ./email -> ./email/caixa",
        directory: "Pasta da demo (temporária, apagada no fim): ",
    });
}
