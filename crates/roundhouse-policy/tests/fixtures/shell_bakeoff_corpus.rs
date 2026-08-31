// crates/roundhouse-policy/tests/fixtures/shell_bakeoff_corpus.rs
//
// A curated, documented corpus standing in for real Claude Code transcript data
// (§1.1/§6.12) until that data can be wired into CI directly. Coverage deliberately
// targets exactly the bash-isms §6.3 cites as brush-parser's reason for existing over
// yash-syntax: array syntax, `[[ ]]`, process substitution, `local`, here-strings — plus
// a healthy majority of plain POSIX-ish commands, since that is still the dominant
// shape of LLM-emitted shell in practice. Each entry states what it EXPECTS: either
// `ShouldParse` (a real, executable bash construct that must not be misclassified
// Opaque — a false-Opaque if it is) or `GenuinelyOpaque` (contains one of §6.3 step 3's
// irreducible hazards, so Opaque is *correct*, not a parser failure).
use roundhouse_policy::shell::classify::OpaqueReason;

pub enum Expectation {
    ShouldParse,
    GenuinelyOpaque(OpaqueReason),
}

pub struct CorpusEntry {
    pub command: &'static str,
    pub expectation: Expectation,
}

pub const BAKEOFF_CORPUS: &[CorpusEntry] = &[
    // --- Array syntax ---
    CorpusEntry {
        command: "arr=(a b c); echo \"${arr[1]}\"",
        expectation: Expectation::ShouldParse,
    },
    CorpusEntry {
        command: "declare -A map=([a]=1 [b]=2)",
        expectation: Expectation::ShouldParse,
    },
    CorpusEntry {
        command: "local -a items=(1 2 3)",
        expectation: Expectation::ShouldParse,
    },
    CorpusEntry {
        command: "arr+=(1 2)",
        expectation: Expectation::ShouldParse,
    },
    CorpusEntry {
        command: "echo \"${#arr[@]}\"",
        expectation: Expectation::ShouldParse,
    },
    CorpusEntry {
        command: "printf '%s\\n' \"${arr[@]}\"",
        expectation: Expectation::ShouldParse,
    },
    CorpusEntry {
        command: "for x in \"${arr[@]}\"; do echo \"$x\"; done",
        expectation: Expectation::ShouldParse,
    },
    CorpusEntry {
        command: "unset 'arr[2]'",
        expectation: Expectation::ShouldParse,
    },
    // --- [[ ]] conditional expressions ---
    CorpusEntry {
        command: "[[ -f file.txt ]] && echo exists",
        expectation: Expectation::ShouldParse,
    },
    CorpusEntry {
        command: "[[ \"$x\" == y* ]]",
        expectation: Expectation::ShouldParse,
    },
    CorpusEntry {
        command: "[[ $a -eq $b ]]",
        expectation: Expectation::ShouldParse,
    },
    CorpusEntry {
        command: "[[ $str =~ ^[0-9]+$ ]]",
        expectation: Expectation::ShouldParse,
    },
    CorpusEntry {
        command: "[[ -n $VAR && -d /tmp ]]",
        expectation: Expectation::ShouldParse,
    },
    CorpusEntry {
        command: "while [[ $i -lt 10 ]]; do i=$((i+1)); done",
        expectation: Expectation::ShouldParse,
    },
    CorpusEntry {
        command: "[[ -z ${VAR:-} ]] || echo set",
        expectation: Expectation::ShouldParse,
    },
    // --- local ---
    CorpusEntry {
        command: "local x=1",
        expectation: Expectation::ShouldParse,
    },
    CorpusEntry {
        command: "local -i count=0",
        expectation: Expectation::ShouldParse,
    },
    CorpusEntry {
        command: "func() { local result; result=$1; echo \"$result\"; }",
        expectation: Expectation::ShouldParse,
    },
    CorpusEntry {
        command: "local -r CONST=frozen",
        expectation: Expectation::ShouldParse,
    },
    // --- here-strings ---
    CorpusEntry {
        command: "read -r line <<< \"hello world\"",
        expectation: Expectation::ShouldParse,
    },
    CorpusEntry {
        command: "mapfile -t lines <<< \"$data\"",
        expectation: Expectation::ShouldParse,
    },
    CorpusEntry {
        command: "IFS=',' read -ra parts <<< \"$csv\"",
        expectation: Expectation::ShouldParse,
    },
    CorpusEntry {
        command: "grep -c foo <<< \"$haystack\"",
        expectation: Expectation::ShouldParse,
    },
    // --- other bash-isms ---
    CorpusEntry {
        command: "case \"$1\" in start) echo starting;; *) echo other;; esac",
        expectation: Expectation::ShouldParse,
    },
    CorpusEntry {
        command: "function greet() { echo hi; }",
        expectation: Expectation::ShouldParse,
    },
    CorpusEntry {
        command: "set -euo pipefail",
        expectation: Expectation::ShouldParse,
    },
    CorpusEntry {
        command: "trap 'echo cleanup' EXIT",
        expectation: Expectation::ShouldParse,
    },
    CorpusEntry {
        command: "shopt -s nullglob",
        expectation: Expectation::ShouldParse,
    },
    CorpusEntry {
        command: "echo \"${var:-default}\"",
        expectation: Expectation::ShouldParse,
    },
    CorpusEntry {
        command: "echo \"${var:=default}\"",
        expectation: Expectation::ShouldParse,
    },
    CorpusEntry {
        command: "echo \"${var#prefix}\"",
        expectation: Expectation::ShouldParse,
    },
    CorpusEntry {
        command: "echo \"${var%%suffix}\"",
        expectation: Expectation::ShouldParse,
    },
    CorpusEntry {
        command: "declare -i n=5",
        expectation: Expectation::ShouldParse,
    },
    CorpusEntry {
        command: "readonly CONST=1",
        expectation: Expectation::ShouldParse,
    },
    CorpusEntry {
        command: "printf -v result '%s' \"$input\"",
        expectation: Expectation::ShouldParse,
    },
    // --- plain POSIX-ish commands (the still-dominant shape) ---
    CorpusEntry {
        command: "git status",
        expectation: Expectation::ShouldParse,
    },
    CorpusEntry {
        command: "git commit -m \"message\"",
        expectation: Expectation::ShouldParse,
    },
    CorpusEntry {
        command: "git log --oneline -n 10",
        expectation: Expectation::ShouldParse,
    },
    CorpusEntry {
        command: "npm test",
        expectation: Expectation::ShouldParse,
    },
    CorpusEntry {
        command: "cargo build --release",
        expectation: Expectation::ShouldParse,
    },
    CorpusEntry {
        command: "cargo test -p roundhouse-policy",
        expectation: Expectation::ShouldParse,
    },
    CorpusEntry {
        command: "ls -la /tmp",
        expectation: Expectation::ShouldParse,
    },
    CorpusEntry {
        command: "mkdir -p foo/bar",
        expectation: Expectation::ShouldParse,
    },
    CorpusEntry {
        command: "rm -rf ./build",
        expectation: Expectation::ShouldParse,
    },
    CorpusEntry {
        command: "cp -r src dst",
        expectation: Expectation::ShouldParse,
    },
    CorpusEntry {
        command: "mv old.txt new.txt",
        expectation: Expectation::ShouldParse,
    },
    CorpusEntry {
        command: "echo \"$HOME/notes.txt\"",
        expectation: Expectation::ShouldParse,
    },
    CorpusEntry {
        command: "export PATH=\"$PATH:/usr/local/bin\"",
        expectation: Expectation::ShouldParse,
    },
    CorpusEntry {
        command: "unset FOO",
        expectation: Expectation::ShouldParse,
    },
    CorpusEntry {
        command: "grep -rn TODO src/",
        expectation: Expectation::ShouldParse,
    },
    CorpusEntry {
        command: "find . -name '*.rs' -newer Cargo.toml",
        expectation: Expectation::ShouldParse,
    },
    CorpusEntry {
        command: "sed -n '1,20p' file.txt",
        expectation: Expectation::ShouldParse,
    },
    CorpusEntry {
        command: "chmod +x script.sh",
        expectation: Expectation::ShouldParse,
    },
    CorpusEntry {
        command: "touch new-file.txt",
        expectation: Expectation::ShouldParse,
    },
    CorpusEntry {
        command: "diff a.txt b.txt",
        expectation: Expectation::ShouldParse,
    },
    CorpusEntry {
        command: "wc -l file.txt",
        expectation: Expectation::ShouldParse,
    },
    CorpusEntry {
        command: "head -n 50 file.txt",
        expectation: Expectation::ShouldParse,
    },
    CorpusEntry {
        command: "tail -f log.txt",
        expectation: Expectation::ShouldParse,
    },
    CorpusEntry {
        command: "cargo fmt --check",
        expectation: Expectation::ShouldParse,
    },
    CorpusEntry {
        command: "cargo clippy -- -D warnings",
        expectation: Expectation::ShouldParse,
    },
    CorpusEntry {
        command: "docker ps -a",
        expectation: Expectation::ShouldParse,
    },
    CorpusEntry {
        command: "kubectl get pods -n default",
        expectation: Expectation::ShouldParse,
    },
    CorpusEntry {
        command: "curl -sS https://example.com/health",
        expectation: Expectation::ShouldParse,
    },
    CorpusEntry {
        command: "echo \"pipeline: $(true)\" > /dev/null; git status && git diff --stat",
        expectation: Expectation::ShouldParse,
    },
    // --- genuinely opaque: command substitution ---
    CorpusEntry {
        command: "echo $(whoami)",
        expectation: Expectation::GenuinelyOpaque(OpaqueReason::CommandSubstitution),
    },
    CorpusEntry {
        command: "result=$(curl -sS https://example.com/data)",
        expectation: Expectation::GenuinelyOpaque(OpaqueReason::CommandSubstitution),
    },
    CorpusEntry {
        command: "echo `whoami`",
        expectation: Expectation::GenuinelyOpaque(OpaqueReason::CommandSubstitution),
    },
    // --- genuinely opaque: process substitution ---
    CorpusEntry {
        command: "diff <(sort a.txt) <(sort b.txt)",
        expectation: Expectation::GenuinelyOpaque(OpaqueReason::ProcessSubstitution),
    },
    CorpusEntry {
        command: "cat <(echo hello)",
        expectation: Expectation::GenuinelyOpaque(OpaqueReason::ProcessSubstitution),
    },
    // --- genuinely opaque: eval ---
    CorpusEntry {
        command: "eval \"$cmd\"",
        expectation: Expectation::GenuinelyOpaque(OpaqueReason::Eval),
    },
    // --- genuinely opaque: source ---
    CorpusEntry {
        command: "source ./script.sh",
        expectation: Expectation::GenuinelyOpaque(OpaqueReason::Source),
    },
    CorpusEntry {
        command: ". ./script.sh",
        expectation: Expectation::GenuinelyOpaque(OpaqueReason::Source),
    },
    // --- genuinely opaque: heredoc ---
    CorpusEntry {
        command: "cat <<'EOF'\nsome content\nEOF",
        expectation: Expectation::GenuinelyOpaque(OpaqueReason::HereDoc),
    },
    CorpusEntry {
        command: "python3 <<PYEOF\nprint(1)\nPYEOF",
        expectation: Expectation::GenuinelyOpaque(OpaqueReason::HereDoc),
    },
    // --- genuinely opaque: backgrounding ---
    CorpusEntry {
        command: "long_running_task &",
        expectation: Expectation::GenuinelyOpaque(OpaqueReason::Backgrounding),
    },
    CorpusEntry {
        command: "nohup server --daemonize &",
        expectation: Expectation::GenuinelyOpaque(OpaqueReason::Backgrounding),
    },
];
