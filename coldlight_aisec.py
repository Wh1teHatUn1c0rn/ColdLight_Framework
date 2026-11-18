#!/usr/bin/env python3
"""
ColdLight AI/ML security assessment: static review of AI systems and the
artifacts they load.

Our existing code scanner knows nothing about AI systems, so a repository
that loads pickle-based checkpoints and trusts remote model code reads as
assessed and clean. This closes that gap, and adds an `ai_ml` class to the
assurance ledger so its absence is visible when it has not been run.

The findings here are mostly NOT novel AI problems -- they are classic
weaknesses wearing new clothes, which is why they get missed:

  * Loading a pickle-based model is CWE-502 deserialisation. `torch.load()`
    without `weights_only=True` executes whatever the file says, so a model
    downloaded from a hub is remote code execution with extra steps.
  * `trust_remote_code=True` runs arbitrary Python from a model repository.
    It is documented behaviour, not a bug, and it is routinely set by people
    copying a quickstart.
  * Passing model output into eval, a shell or SQL is the same injection it
    always was -- the model is simply a new untrusted source.

Findings map to the OWASP Top 10 for LLM Applications (2025) and, where we are
confident of the identifier, to MITRE ATLAS. ATLAS mappings are indicative:
where no identifier is given it is because we would be guessing, not because
none applies.

SCOPE BOUNDARY: static analysis only. This reads source and inspects model
files BYTE-WISE -- it never deserialises one, because deserialising an
untrusted model is the very vulnerability being reported. Nothing here probes
a live model, generates adversarial prompts, or attempts a jailbreak.

Stdlib only. Read-only.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path

from coldlight_codescan import (
    MAX_FILE_BYTES,
    MAX_LINE_LEN,
    SEVERITY_ORDER,
    SKIP_DIRS,
    SUPPRESS_RE,
    redact,
)

# Severities here are our own judgement, as in the code scanner.
SEVERITY_SOURCE = "coldlight-rule"

# ---------------------------------------------------------------------------
# OWASP Top 10 for LLM Applications (2025)
# ---------------------------------------------------------------------------

OWASP_LLM = {
    "LLM01": "Prompt Injection",
    "LLM02": "Sensitive Information Disclosure",
    "LLM03": "Supply Chain",
    "LLM04": "Data and Model Poisoning",
    "LLM05": "Improper Output Handling",
    "LLM06": "Excessive Agency",
    "LLM07": "System Prompt Leakage",
    "LLM08": "Vector and Embedding Weaknesses",
    "LLM09": "Misinformation",
    "LLM10": "Unbounded Consumption",
}

# MITRE ATLAS, used only where the identifier is certain.
ATLAS = {
    "AML.T0010": "ML Supply Chain Compromise",
    "AML.T0018": "Backdoor ML Model",
    "AML.T0020": "Poison Training Data",
    "AML.T0024": "Exfiltration via ML Inference API",
    "AML.T0051": "LLM Prompt Injection",
    "AML.T0054": "LLM Jailbreak",
}

PY = frozenset({".py", ".pyw", ".ipynb"})
JS = frozenset({".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx"})
CONFIGISH = frozenset({".yml", ".yaml", ".json", ".toml", ".env", ".cfg",
                       ".ini"})

TEXT_EXTENSIONS = PY | JS | CONFIGISH

# Model/artifact formats. Pickle-based formats execute code on load; the
# safetensors format exists precisely to avoid that.
UNSAFE_MODEL_EXTENSIONS = {
    ".pkl": "pickle",
    ".pickle": "pickle",
    ".pt": "torch (zip of pickle)",
    ".pth": "torch (zip of pickle)",
    ".bin": "pickle or raw weights",
    ".joblib": "joblib (pickle)",
    ".h5": "keras HDF5 (can embed Lambda layers)",
    ".hdf5": "keras HDF5 (can embed Lambda layers)",
    ".npy": "numpy (unsafe with allow_pickle)",
    ".npz": "numpy (unsafe with allow_pickle)",
    ".model": "format-dependent",
    ".ckpt": "checkpoint (often pickle)",
}
SAFE_MODEL_EXTENSIONS = {
    ".safetensors": "safetensors",
    ".onnx": "ONNX (graph, no code execution)",
    ".gguf": "GGUF",
    ".tflite": "TFLite",
}

# Pickle protocol 2+ opcode. Detected by reading two bytes -- never by
# unpickling, which is the vulnerability itself.
_PICKLE_MAGIC = b"\x80"
_ZIP_MAGIC = b"PK\x03\x04"


@dataclass
class AiRule:
    rule_id: str
    severity: str
    title: str
    pattern: re.Pattern
    remediation: str
    owasp: str = ""              # LLM01..LLM10
    cwe: str = ""
    atlas: str = ""              # only where we are sure
    extensions: frozenset[str] | None = None
    redact: bool = False


def _rx(pattern: str, flags=0) -> re.Pattern:
    return re.compile(pattern, flags)


RULES: list[AiRule] = [
    # ---- LLM03 supply chain: loading code disguised as data --------------
    AiRule(
        "AI-TORCH-LOAD-UNSAFE", "HIGH",
        "torch.load without weights_only=True",
        _rx(r"\btorch\s*\.\s*load\s*\((?![^)]*weights_only\s*=\s*True)"),
        "Pass weights_only=True (default since torch 2.6) so only tensors are "
        "read. Prefer a .safetensors checkpoint, which cannot carry code.",
        owasp="LLM03", cwe="CWE-502", atlas="AML.T0010", extensions=PY),
    AiRule(
        "AI-TRUST-REMOTE-CODE", "HIGH",
        "trust_remote_code=True executes code from the model repo",
        _rx(r"\btrust_remote_code\s*=\s*True\b"),
        "Remove it, or pin an exact revision you have reviewed "
        "(revision='<commit sha>') and vendor the code into your repository "
        "so changes go through review.",
        owasp="LLM03", cwe="CWE-494", atlas="AML.T0010", extensions=PY),
    AiRule(
        "AI-PICKLE-MODEL-LOAD", "HIGH",
        "Model loaded through pickle or joblib",
        _rx(r"\b(?:joblib|pickle|cloudpickle|dill)\s*\.\s*loads?\s*\("),
        "Deserialising an untrusted model is arbitrary code execution. Use "
        "safetensors, or treat the artifact as code and review its provenance.",
        owasp="LLM03", cwe="CWE-502", atlas="AML.T0010", extensions=PY),
    AiRule(
        "AI-NUMPY-ALLOW-PICKLE", "MEDIUM",
        "numpy load with allow_pickle=True",
        _rx(r"\bnp(?:umpy)?\s*\.\s*load\s*\([^)]*allow_pickle\s*=\s*True"),
        "Leave allow_pickle at its default of False; store arrays in a format "
        "that does not execute code.",
        owasp="LLM03", cwe="CWE-502", extensions=PY),
    AiRule(
        "AI-KERAS-UNSAFE-LOAD", "MEDIUM",
        "Keras model loaded without safe_mode",
        _rx(r"\b(?:keras|tf\.keras)[\w.]*\.models?\s*\.\s*load_model\s*\("
            r"(?![^)]*safe_mode\s*=\s*True)"),
        "Pass safe_mode=True so Lambda layers (which carry arbitrary Python) "
        "are refused.",
        owasp="LLM03", cwe="CWE-502", extensions=PY),
    AiRule(
        "AI-UNPINNED-MODEL-REF", "LOW",
        "Model loaded from a hub without a pinned revision",
        _rx(r"\bfrom_pretrained\s*\(\s*[\"'][^\"']+[\"']\s*(?![^)]*revision\s*=)"),
        "Pin revision='<commit sha>'. A floating tag means the artifact can "
        "change under you, which is a supply-chain path.",
        owasp="LLM03", atlas="AML.T0010", extensions=PY),

    # ---- LLM05 improper output handling: the model is untrusted input ----
    AiRule(
        "AI-OUTPUT-TO-EVAL", "CRITICAL",
        "Model output passed to eval/exec",
        _rx(r"(?i)\b(?:eval|exec)\s*\(\s*[^)]*\b(?:completion|response|"
            r"message|answer|output|generated|llm_?result|choices)\b"),
        "Never execute model output. Parse it as data, or constrain it to an "
        "allow-list of permitted actions.",
        owasp="LLM05", cwe="CWE-95", extensions=PY | JS),
    AiRule(
        "AI-OUTPUT-TO-SHELL", "CRITICAL",
        "Model output passed to a shell",
        _rx(r"(?i)\b(?:os\.system|subprocess\.(?:run|call|Popen)|child_process"
            r"\s*\.\s*exec)\s*\([^)]*\b(?:completion|response|message|answer|"
            r"output|generated|llm_?result|tool_?call)\b"),
        "Pass an argument list, and allow-list the permitted commands. Model "
        "output is attacker-influenceable whenever the prompt is.",
        owasp="LLM05", cwe="CWE-78", extensions=PY | JS),
    AiRule(
        "AI-OUTPUT-TO-SQL", "HIGH",
        "Model output interpolated into SQL",
        # Require a SQL verb in the string, then the interpolation. The
        # earlier form demanded the placeholder sit immediately inside the
        # quotes, which missed `WHERE body = '{response}'` -- the quoting
        # that makes it injectable was what stopped it matching -- and
        # missed concatenation entirely. The SQL verb is what keeps this off
        # innocent f-strings like query(f"_dmarc.{domain}").
        _rx(r"(?i)\b(?:execute|executemany|query)\s*\(\s*f?[\"'][^\n]{0,200}?"
            r"\b(?:select|insert|update|delete|where|from)\b[^\n]{0,200}?"
            r"(?:\{\s*|[\"']\s*(?:\+|%|,)\s*)"
            r"(?:completion|response|answer|output|generated)\b"),
        "Use parameterised queries, and validate any model-proposed identifier "
        "against a fixed allow-list.",
        owasp="LLM05", cwe="CWE-89", extensions=PY | JS),
    AiRule(
        "AI-OUTPUT-TO-INNERHTML", "HIGH",
        "Model output written to innerHTML",
        _rx(r"\.(?:inner|outer)HTML\s*=\s*[^;]*\b(?:completion|response|"
            r"message|answer|output|generated|markdown)\b"),
        "Render as text, or sanitise with DOMPurify. Model output can contain "
        "markup and script.",
        owasp="LLM05", cwe="CWE-79", extensions=JS),

    # ---- LLM01 prompt injection -----------------------------------------
    AiRule(
        "AI-PROMPT-FROM-REQUEST", "MEDIUM",
        "Prompt built directly from request data",
        _rx(r"(?i)(?:prompt|system_?prompt|messages)\s*=\s*f?[\"'][^\"']*\{"
            r"[^}]*\b(?:request|req|params|query|body|user_?input)\b"),
        "Keep untrusted text in a clearly delimited user turn, never in the "
        "system prompt, and treat any instruction it contains as data. "
        "Constrain what the model can do rather than trying to sanitise the "
        "prompt.",
        owasp="LLM01", cwe="CWE-74", atlas="AML.T0051", extensions=PY | JS),
    AiRule(
        "AI-RAG-UNTRUSTED-CONTEXT", "MEDIUM",
        "Retrieved documents concatenated into the prompt",
        _rx(r"(?i)(?:prompt|context)\s*(?:=|\+=)\s*[^\n]*\b(?:retrieved|"
            r"documents|chunks|search_?results|similar)\b"),
        "Indirect prompt injection: a poisoned document becomes instructions. "
        "Delimit retrieved content, label it as untrusted, and do not grant "
        "the model tools it should not use on that content's say-so.",
        owasp="LLM08", cwe="CWE-74", atlas="AML.T0051", extensions=PY | JS),

    # ---- LLM06 excessive agency -----------------------------------------
    AiRule(
        "AI-AGENT-SHELL-TOOL", "HIGH",
        "Agent given an unconstrained shell or exec tool",
        # Agent tool lists are written as dicts and YAML at least as often as
        # assignments, so accept ":" as well as "=".
        _rx(r"(?i)[\"']?(?:tool|function)s?[\"']?\s*[:=]\s*.*"
            r"\b(?:shell|bash|terminal|run_?command|execute_?code|"
            r"python_?repl)\b"),
        "Scope the tool: an allow-list of commands, a container with no "
        "credentials, and human confirmation for anything irreversible.",
        owasp="LLM06", cwe="CWE-269", extensions=PY | JS | CONFIGISH),
    AiRule(
        "AI-AGENT-AUTO-APPROVE", "MEDIUM",
        "Tool calls auto-approved",
        # The ["']? before the separator matters: in a dict or JSON config
        # the key's closing quote sits between the name and the colon, as in
        # `"auto_approve": True`, and without it the rule misses every
        # config file it most needs to read.
        _rx(r"(?i)\b(?:auto_?approve|require_?(?:approval|confirmation)|"
            r"human_?in_?the_?loop)[\"']?\s*[:=]\s*"
            r"(?:True|true|False|false)\b"),
        "Confirm the direction of this setting. Irreversible or outward-facing "
        "actions should require explicit approval.",
        owasp="LLM06", cwe="CWE-269", extensions=PY | JS | CONFIGISH),

    # ---- LLM02 / LLM07 disclosure ---------------------------------------
    AiRule(
        "AI-SECRET-OPENAI", "CRITICAL",
        "OpenAI API key committed to source",
        # Anthropic keys also begin "sk-", so exclude them explicitly:
        # telling someone to revoke the wrong provider's key is worse than
        # a vague finding.
        _rx(r"\bsk-(?!ant-)(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{20,}\b"),
        "Revoke the key at the provider, then load it from the environment or "
        "a secrets manager.",
        owasp="LLM02", cwe="CWE-798", redact=True),
    AiRule(
        "AI-SECRET-ANTHROPIC", "CRITICAL",
        "Anthropic API key committed to source",
        _rx(r"\bsk-ant-[A-Za-z0-9_-]{20,}\b"),
        "Revoke the key at the provider, then load it from the environment or "
        "a secrets manager.",
        owasp="LLM02", cwe="CWE-798", redact=True),
    AiRule(
        "AI-SECRET-HUGGINGFACE", "HIGH",
        "Hugging Face token committed to source",
        _rx(r"\bhf_[A-Za-z0-9]{30,}\b"),
        "Revoke the token in your Hugging Face settings and use a short-lived "
        "one.",
        owasp="LLM02", cwe="CWE-798", redact=True),
    AiRule(
        "AI-SECRET-GENERIC-LLM", "HIGH",
        "AI provider credential assigned in source",
        _rx(r"(?i)\b(?:openai|anthropic|cohere|replicate|together|groq|"
            r"mistral|gemini|huggingface|hf)_?(?:api_?)?(?:key|token|secret)\b"
            r"\s*[:=]\s*(['\"])(?![\s{<$])[^'\"\n]{12,}\1"),
        "Load provider credentials from the environment or a secrets manager, "
        "and rotate anything that has been committed.",
        owasp="LLM02", cwe="CWE-798", redact=True),
    AiRule(
        "AI-PROMPT-LOGS-PII", "MEDIUM",
        "Prompts or completions written to logs",
        _rx(r"(?i)\b(?:log(?:ger)?|print)\b[^\n]{0,40}\b(?:prompt|completion|"
            r"messages|user_?input|response\.choices)\b"),
        "Prompts and completions routinely contain personal data and secrets. "
        "Redact before logging, and set a retention period.",
        owasp="LLM02", cwe="CWE-312", extensions=PY | JS),

    # ---- LLM10 unbounded consumption ------------------------------------
    AiRule(
        "AI-NO-TOKEN-LIMIT", "LOW",
        "Model call without a token or output ceiling",
        _rx(r"(?i)\.(?:create|generate|invoke|chat)\s*\((?![^)]*max_?"
            r"(?:tokens|output_?tokens|new_?tokens))[^)]*\bmodel\s*="),
        "Set max_tokens and a request timeout. Without a ceiling, cost and "
        "latency scale with whatever the caller sends.",
        owasp="LLM10", cwe="CWE-400", atlas="AML.T0024", extensions=PY | JS),
]


# ---------------------------------------------------------------------------
# Findings
# ---------------------------------------------------------------------------

@dataclass
class AiFinding:
    rule_id: str
    severity: str
    title: str
    file: str
    line: int
    snippet: str = ""
    remediation: str = ""
    owasp: str = ""
    owasp_name: str = ""
    cwe: str = ""
    atlas: str = ""
    atlas_name: str = ""
    severity_source: str = SEVERITY_SOURCE

    def to_dict(self) -> dict:
        return asdict(self)

    @property
    def rank(self) -> tuple:
        return (-SEVERITY_ORDER.get(self.severity.upper(), 0), self.file,
                self.line)


@dataclass
class ModelArtifact:
    path: str
    extension: str
    format_note: str
    bytes: int
    safe_format: bool
    pickle_detected: bool = False

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class AiScanResult:
    findings: list[AiFinding] = field(default_factory=list)
    artifacts: list[ModelArtifact] = field(default_factory=list)
    files_scanned: int = 0
    notebooks_scanned: int = 0
    errors: list[str] = field(default_factory=list)

    @property
    def unsafe_artifacts(self) -> list[ModelArtifact]:
        return [a for a in self.artifacts if not a.safe_format]


# ---------------------------------------------------------------------------
# Scanning source
# ---------------------------------------------------------------------------

def _notebook_lines(text: str):
    """Yield (line_number, source_line) for a Jupyter notebook.

    Code cells and, importantly, their stored OUTPUT -- a notebook committed
    with an API key printed in a cell result leaks it just as surely as source.
    """
    try:
        document = json.loads(text)
    except ValueError:
        return
    counter = 0
    for cell in document.get("cells") or []:
        for line in cell.get("source") or []:
            counter += 1
            yield counter, line.rstrip("\n")
        for output in cell.get("outputs") or []:
            for line in (output.get("text") or []):
                counter += 1
                yield counter, str(line).rstrip("\n")
            data = (output.get("data") or {}).get("text/plain") or []
            for line in data:
                counter += 1
                yield counter, str(line).rstrip("\n")


def scan_file(path: Path, rules: list[AiRule] | None = None) -> list[AiFinding]:
    rules = rules if rules is not None else RULES
    extension = path.suffix.lower()
    applicable = [r for r in rules
                  if r.extensions is None or extension in r.extensions]
    if not applicable:
        return []

    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []

    if extension == ".ipynb":
        lines = list(_notebook_lines(text))
    else:
        lines = list(enumerate(text.splitlines(), start=1))

    findings: list[AiFinding] = []
    for lineno, line in lines:
        if len(line) > MAX_LINE_LEN or SUPPRESS_RE.search(line):
            continue
        stripped = line.strip()
        if stripped.startswith(("#", "//", "*")):
            continue

        for rule in applicable:
            if not rule.pattern.search(line):
                continue
            snippet = redact(line) if rule.redact else line
            findings.append(AiFinding(
                rule_id=rule.rule_id,
                severity=rule.severity,
                title=rule.title,
                file=str(path),
                line=lineno,
                snippet=snippet.strip()[:200],
                remediation=rule.remediation,
                owasp=rule.owasp,
                owasp_name=OWASP_LLM.get(rule.owasp, ""),
                cwe=rule.cwe,
                atlas=rule.atlas,
                atlas_name=ATLAS.get(rule.atlas, ""),
            ))
    return findings


# ---------------------------------------------------------------------------
# Model artifacts -- inspected by bytes, never deserialised
# ---------------------------------------------------------------------------

def inspect_artifact(path: Path) -> ModelArtifact | None:
    """Classify a model file by extension and magic bytes.

    This NEVER calls pickle.load, torch.load or anything equivalent --
    deserialising an untrusted model is exactly the vulnerability being
    reported, so inspection reads a handful of bytes and nothing more.
    """
    extension = path.suffix.lower()
    if extension in SAFE_MODEL_EXTENSIONS:
        note, safe = SAFE_MODEL_EXTENSIONS[extension], True
    elif extension in UNSAFE_MODEL_EXTENSIONS:
        note, safe = UNSAFE_MODEL_EXTENSIONS[extension], False
    else:
        return None

    try:
        size = path.stat().st_size
        with open(path, "rb") as handle:
            head = handle.read(4)
    except OSError:
        return None

    pickled = head.startswith(_PICKLE_MAGIC) or head.startswith(_ZIP_MAGIC)
    return ModelArtifact(path=str(path), extension=extension,
                         format_note=note, bytes=size, safe_format=safe,
                         pickle_detected=pickled and not safe)


def iter_files(root: str | Path, exclude: list[str] | None = None):
    from coldlight_codescan import is_excluded

    root = Path(root)
    if root.is_file():
        if not is_excluded(root, root.parent, exclude):
            yield root
        return

    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [
            d for d in dirnames
            if d not in SKIP_DIRS and not (d.startswith(".") and d != ".")
            and not is_excluded(Path(dirpath) / d, root, exclude)
        ]
        for name in filenames:
            path = Path(dirpath) / name
            if is_excluded(path, root, exclude):
                continue
            suffix = path.suffix.lower()
            if (suffix in TEXT_EXTENSIONS or suffix in UNSAFE_MODEL_EXTENSIONS
                    or suffix in SAFE_MODEL_EXTENSIONS):
                yield path


def scan_ai(root: str | Path, rules: list[AiRule] | None = None,
            exclude: list[str] | None = None) -> AiScanResult:
    """Assess AI/ML code and artifacts under `root`. Read-only."""
    result = AiScanResult()

    for path in iter_files(root, exclude):
        suffix = path.suffix.lower()

        if suffix in UNSAFE_MODEL_EXTENSIONS or suffix in SAFE_MODEL_EXTENSIONS:
            artifact = inspect_artifact(path)
            if artifact is not None:
                result.artifacts.append(artifact)
            continue

        try:
            if path.stat().st_size > MAX_FILE_BYTES:
                continue
        except OSError:
            continue

        result.files_scanned += 1
        if suffix == ".ipynb":
            result.notebooks_scanned += 1
        try:
            result.findings.extend(scan_file(path, rules))
        except Exception as exc:  # noqa: BLE001 - one file must not stop a scan
            result.errors.append(f"{path}: {exc}")

    # A committed pickle-format model is itself a finding.
    for artifact in result.unsafe_artifacts:
        if not artifact.pickle_detected:
            continue
        result.findings.append(AiFinding(
            rule_id="AI-PICKLE-ARTIFACT",
            severity="HIGH",
            title=f"Pickle-based model artifact in the repository "
                  f"({artifact.extension})",
            file=artifact.path,
            line=0,
            snippet=f"{artifact.format_note}, {artifact.bytes} bytes",
            remediation="Loading this executes whatever it contains. Convert "
                        "to safetensors, or document its provenance and treat "
                        "it as code under review.",
            owasp="LLM03", owasp_name=OWASP_LLM["LLM03"], cwe="CWE-502",
            atlas="AML.T0010", atlas_name=ATLAS["AML.T0010"],
        ))

    result.findings.sort(key=lambda f: f.rank)
    return result


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------

def severity_counts(findings: list[AiFinding]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for finding in findings:
        counts[finding.severity.upper()] = counts.get(
            finding.severity.upper(), 0) + 1
    return counts


def owasp_counts(findings: list[AiFinding]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for finding in findings:
        if finding.owasp:
            counts[finding.owasp] = counts.get(finding.owasp, 0) + 1
    return dict(sorted(counts.items()))


def meets_threshold(findings: list[AiFinding], threshold: str) -> bool:
    floor = SEVERITY_ORDER.get((threshold or "").upper())
    if floor is None:
        raise ValueError(f"unknown severity threshold: {threshold!r}")
    return any(SEVERITY_ORDER.get(f.severity.upper(), 0) >= floor
               for f in findings)


def text_report(result: AiScanResult, *, show_remediation: bool = True) -> str:
    out: list[str] = []
    out.append("=" * 70)
    out.append("ColdLight AI/ML security assessment")
    out.append("=" * 70)
    out.append(f"files scanned   : {result.files_scanned}"
               + (f" ({result.notebooks_scanned} notebook(s))"
                  if result.notebooks_scanned else ""))
    out.append(f"model artifacts : {len(result.artifacts)}"
               + (f", {len(result.unsafe_artifacts)} in a code-executing format"
                  if result.unsafe_artifacts else ""))
    out.append(f"findings        : {len(result.findings)}")

    counts = severity_counts(result.findings)
    if counts:
        ordered = sorted(counts.items(),
                         key=lambda kv: -SEVERITY_ORDER.get(kv[0], 0))
        out.append("  by severity   : "
                   + ", ".join(f"{k.lower()}={v}" for k, v in ordered))
    owasp = owasp_counts(result.findings)
    if owasp:
        out.append("  OWASP LLM     : "
                   + ", ".join(f"{k} {OWASP_LLM.get(k, '')}" for k in owasp))

    if result.artifacts:
        out.append("")
        out.append("Model artifacts (inspected by bytes; never deserialised):")
        for artifact in result.artifacts:
            marker = "SAFE  " if artifact.safe_format else "UNSAFE"
            pickled = " [pickle/zip magic]" if artifact.pickle_detected else ""
            out.append(f"  {marker} {artifact.extension:<13} "
                       f"{artifact.format_note}{pickled}")
            out.append(f"         {artifact.path}")

    if result.findings:
        out.append("")
        current = None
        for finding in result.findings:
            if finding.rule_id != current:
                current = finding.rule_id
                tags = " ".join(x for x in (finding.owasp, finding.cwe,
                                            finding.atlas) if x)
                out.append(f"{finding.severity.upper():<9} {tags:<28} "
                           f"{finding.title}  [{finding.rule_id}]")
                if finding.owasp_name:
                    out.append(f"          OWASP {finding.owasp} "
                               f"{finding.owasp_name}"
                               + (f"  |  ATLAS {finding.atlas} "
                                  f"{finding.atlas_name}"
                                  if finding.atlas_name else ""))
                if show_remediation and finding.remediation:
                    out.append(f"          fix: {finding.remediation}")
            location = (f"{finding.file}:{finding.line}" if finding.line
                        else finding.file)
            out.append(f"          {location}")
            if finding.snippet:
                out.append(f"              | {finding.snippet}")
        out.append("")

    if result.errors:
        out.append(f"{len(result.errors)} error(s):")
        for error in result.errors[:10]:
            out.append(f"  - {error}")

    out.append("Static analysis only: no model was loaded, probed or "
               "adversarially tested. Pair with a live evaluation harness for "
               "susceptibility testing.")
    return "\n".join(out)


def json_report(result: AiScanResult) -> dict:
    return {
        "tool": "coldlight aisec",
        "files_scanned": result.files_scanned,
        "notebooks_scanned": result.notebooks_scanned,
        "severity_counts": severity_counts(result.findings),
        "owasp_llm_counts": owasp_counts(result.findings),
        "model_artifacts": [a.to_dict() for a in result.artifacts],
        "unsafe_artifact_count": len(result.unsafe_artifacts),
        "findings": [f.to_dict() for f in result.findings],
        "errors": result.errors,
    }
