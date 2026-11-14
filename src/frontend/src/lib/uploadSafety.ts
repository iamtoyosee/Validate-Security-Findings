import type { UploadEntry } from "../types";

// ---------------------------------------------------------------------------
// Upload preflight.
//
// Runs entirely in the browser BEFORE anything is sent. The goal is that only the
// files the scanners actually need ever leave the user's machine, and that obvious
// secrets never do. This is a convenience + defence-in-depth layer, not a security
// boundary: the backend must still enforce its own limits (see roadmap doc).
// ---------------------------------------------------------------------------

/** Directories that are never source the user wrote. */
const SKIP_DIRS = new Set([
  ".git", ".hg", ".svn", "node_modules", "__pycache__", ".venv", "venv", "env", ".env",
  ".tox", ".nox", ".mypy_cache", ".pytest_cache", ".ruff_cache", "site-packages",
  "dist", "build", ".eggs", ".idea", ".vscode", ".next", "coverage", "htmlcov",
]);

/** Files that commonly hold credentials - blocked outright, never uploaded. */
const SENSITIVE_PATTERNS: { re: RegExp; why: string }[] = [
  { re: /(^|\/)\.env(\.[\w.-]+)?$/i, why: "Environment file (usually holds secrets)" },
  { re: /\.(pem|key|p12|pfx|jks|keystore|crt|cer|der)$/i, why: "Key or certificate" },
  { re: /(^|\/)id_(rsa|dsa|ecdsa|ed25519)(\.pub)?$/i, why: "SSH key" },
  { re: /(^|\/)(credentials|secrets?)(\.[\w]+)?$/i, why: "Credentials file" },
  { re: /(^|\/)(\.npmrc|\.pypirc|\.netrc|\.htpasswd|\.git-credentials)$/i, why: "Auth config" },
  { re: /(^|\/)\.aws\//i, why: "AWS config" },
  { re: /\.(sqlite3?|db)$/i, why: "Database file (may contain user data)" },
];

/** What the scanners can actually use today (Python-only engine). */
const SCANNABLE = [
  /\.pyi?$/i,
  /\.(html?|jinja2?|j2)$/i, // templates - Semgrep has Flask/Django template XSS rules
  /(^|\/)(requirements[\w.-]*\.txt|pyproject\.toml|setup\.(py|cfg)|Pipfile)$/i,
];

export const MAX_FILE_BYTES = 1_000_000;
export const MAX_TOTAL_BYTES = 10_000_000;
/** Mirrors LocalPathSource(max_lines=5000) in src/codebase_source.py. */
export const MAX_PYTHON_LINES = 5000;

// Likely hardcoded credentials. Each pattern captures the secret value in group 1
// so redaction can replace only that span, leaving line numbers and columns intact
// (findings must still point at the right place).
const SECRET_PATTERNS: { name: string; re: RegExp }[] = [
  { name: "AWS access key", re: /\b(AKIA[0-9A-Z]{16})\b/g },
  { name: "GitHub token", re: /\b(gh[pousr]_[A-Za-z0-9]{36,})\b/g },
  { name: "Slack token", re: /\b(xox[abprs]-[A-Za-z0-9-]{10,})\b/g },
  { name: "Stripe key", re: /\b((?:sk|rk)_live_[A-Za-z0-9]{20,})\b/g },
  { name: "Private key block", re: /(-----BEGIN [A-Z ]*PRIVATE KEY-----)/g },
  {
    // Covers `key = "…"`, `"key": "…"` (dict/JSON) and `key: str = "…"` (annotated).
    name: "Hardcoded credential",
    re: /(?:password|passwd|secret|api_?key|api_?token|access_?token|auth_?token|token|client_secret)["']?\s*(?::\s*\w+\s*)?[:=]\s*["']([^"'\s]{8,})["']/gi,
  },
];

export type ExcludeReason = "dependency" | "sensitive" | "unsupported" | "too-large" | "excluded-by-you";

export interface ExcludedFile {
  path: string;
  reason: ExcludeReason;
  detail: string;
}

export interface SecretHit {
  path: string;
  line: number;
  kind: string;
}

export interface PreflightReport {
  folderName: string;
  totalFiles: number;
  included: UploadEntry[];
  excluded: ExcludedFile[];
  secrets: SecretHit[];
  includedBytes: number;
  pythonLines: number;
  blockers: string[];
}

export const REASON_LABEL: Record<ExcludeReason, string> = {
  dependency: "Dependencies & tooling",
  sensitive: "Sensitive (blocked)",
  unsupported: "Not scannable",
  "too-large": "Too large",
  "excluded-by-you": "Your exclusions",
};

/** Minimal glob -> RegExp: supports **, *, ?. Patterns match from the folder root;
 *  a pattern with no slash matches at any depth (like .gitignore). */
export function globToRegExp(glob: string): RegExp {
  // A trailing slash means "this directory": `tests/` == `tests/**`.
  const g = glob.trim().replace(/^\.?\//, "").replace(/\/$/, "/**");
  let re = "";
  for (let i = 0; i < g.length; i++) {
    const c = g[i];
    if (c === "*") {
      if (g[i + 1] === "*") {
        i++;
        if (g[i + 1] === "/") {
          // `**/` = zero or more whole directories, so `**/migrations/**` doesn't
          // also match `notmigrations/`.
          re += "(?:.*/)?";
          i++;
        } else {
          re += ".*";
        }
      } else {
        re += "[^/]*";
      }
    } else if (c === "?") {
      re += "[^/]";
    } else {
      re += c.replace(/[.+^${}()|[\]\\]/g, "\\$&");
    }
  }
  const anchored = g.includes("/") ? `^${re}` : `(^|/)${re}`;
  return new RegExp(`${anchored}($|/)`);
}

export function parseGlobs(text: string): string[] {
  return text
    .split(/[\n,]/)
    .map((s) => s.trim())
    .filter(Boolean);
}

/** Strip the top-level folder so paths are relative to the codebase root. */
function relativeToRoot(path: string): { root: string; rel: string } {
  const parts = path.split("/");
  return parts.length > 1 ? { root: parts[0], rel: parts.slice(1).join("/") } : { root: "", rel: path };
}

export async function runPreflight(entries: UploadEntry[], excludeGlobs: string[]): Promise<PreflightReport> {
  const userExcludes = excludeGlobs.map((g) => ({ g, re: globToRegExp(g) }));
  const included: UploadEntry[] = [];
  const excluded: ExcludedFile[] = [];
  let folderName = "";
  let includedBytes = 0;

  for (const entry of entries) {
    const { root, rel } = relativeToRoot(entry.path);
    folderName ||= root;
    const segments = rel.split("/");

    const skipDir = segments.slice(0, -1).find((s) => SKIP_DIRS.has(s));
    if (skipDir) {
      excluded.push({ path: rel.replace(/\/…$/, "/"), reason: "dependency", detail: `Inside ${skipDir}/` });
      continue;
    }
    const sensitive = SENSITIVE_PATTERNS.find((p) => p.re.test(rel));
    if (sensitive) {
      excluded.push({ path: rel, reason: "sensitive", detail: sensitive.why });
      continue;
    }
    const userHit = userExcludes.find((u) => u.re.test(rel));
    if (userHit) {
      excluded.push({ path: rel, reason: "excluded-by-you", detail: `Matches ${userHit.g}` });
      continue;
    }
    if (!SCANNABLE.some((re) => re.test(rel))) {
      excluded.push({ path: rel, reason: "unsupported", detail: "No scanner uses this file type yet" });
      continue;
    }
    if (entry.file.size > MAX_FILE_BYTES) {
      excluded.push({ path: rel, reason: "too-large", detail: `${formatBytes(entry.file.size)} (limit ${formatBytes(MAX_FILE_BYTES)})` });
      continue;
    }
    included.push(entry);
    includedBytes += entry.file.size;
  }

  // Only now read file contents - and only for files we'd actually send.
  const secrets: SecretHit[] = [];
  let pythonLines = 0;
  await Promise.all(
    included.map(async (entry) => {
      const text = await entry.file.text();
      const rel = relativeToRoot(entry.path).rel;
      if (/\.pyi?$/i.test(rel)) pythonLines += text.split("\n").length;
      for (const hit of findSecrets(text)) secrets.push({ path: rel, ...hit });
    }),
  );
  secrets.sort((a, b) => a.path.localeCompare(b.path) || a.line - b.line);

  const blockers: string[] = [];
  if (included.length === 0) blockers.push("No scannable files found - this tool currently analyzes Python projects.");
  if (pythonLines > MAX_PYTHON_LINES) {
    blockers.push(
      `${pythonLines.toLocaleString()} lines of Python - the server limit is ${MAX_PYTHON_LINES.toLocaleString()}. ` +
        "Add exclusions (e.g. tests/**) or pick a smaller folder.",
    );
  }
  if (includedBytes > MAX_TOTAL_BYTES) {
    blockers.push(`Upload would be ${formatBytes(includedBytes)} - the limit is ${formatBytes(MAX_TOTAL_BYTES)}.`);
  }

  return { folderName, totalFiles: entries.length, included, excluded, secrets, includedBytes, pythonLines, blockers };
}

function findSecrets(text: string): { line: number; kind: string }[] {
  const hits: { line: number; kind: string }[] = [];
  const lines = text.split("\n");
  lines.forEach((line, i) => {
    for (const { name, re } of SECRET_PATTERNS) {
      re.lastIndex = 0;
      if (re.test(line)) hits.push({ line: i + 1, kind: name });
    }
  });
  return hits;
}

/** Replace only the captured secret value with a marker. Newlines are untouched,
 *  so finding line numbers stay correct. */
const PEM_BLOCK = /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g;

export function redactSecrets(text: string): string {
  // Whole key blocks first: every line of the block is replaced, newlines kept.
  let out = text.replace(PEM_BLOCK, (block) =>
    block
      .split("\n")
      .map(() => "REDACTED_BY_UPLOAD_PREFLIGHT")
      .join("\n"),
  );
  for (const { re } of SECRET_PATTERNS) {
    out = out.replace(re, (match, value: string) => match.replace(value, "REDACTED_BY_UPLOAD_PREFLIGHT"));
  }
  return out;
}

/** Build the final list of files to send, redacting where requested. */
export async function prepareUpload(report: PreflightReport, redact: boolean): Promise<UploadEntry[]> {
  const secretPaths = new Set(report.secrets.map((s) => s.path));
  return Promise.all(
    report.included.map(async (entry) => {
      // Send paths relative to the project root (not "my-service/app.py"), so
      // finding paths - and SARIF exports - line up with the user's repo.
      const rel = relativeToRoot(entry.path).rel;
      if (!redact || !secretPaths.has(rel)) return { path: rel, file: entry.file };
      const cleaned = redactSecrets(await entry.file.text());
      return { path: rel, file: new File([cleaned], entry.file.name, { type: entry.file.type }) };
    }),
  );
}

export function formatBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(0)} KB`;
  return `${(n / (1024 * 1024)).toFixed(1)} MB`;
}

// ---------------------------------------------------------------------------
// Drag-and-drop folder traversal (the File System Entries API).
// ---------------------------------------------------------------------------

export async function entriesFromDataTransfer(items: DataTransferItemList): Promise<UploadEntry[]> {
  const roots = Array.from(items)
    .map((item) => item.webkitGetAsEntry?.())
    .filter((e): e is FileSystemEntry => !!e);
  const out: UploadEntry[] = [];
  await Promise.all(roots.map((root) => walk(root, "", out)));
  return out;
}

async function walk(entry: FileSystemEntry, prefix: string, out: UploadEntry[]): Promise<void> {
  const path = prefix ? `${prefix}/${entry.name}` : entry.name;
  if (entry.isFile) {
    const file = await new Promise<File>((resolve, reject) => (entry as FileSystemFileEntry).file(resolve, reject));
    out.push({ path, file });
    return;
  }
  if (entry.isDirectory) {
    // Don't even descend into dependency folders - node_modules can be 100k files.
    if (prefix && SKIP_DIRS.has(entry.name)) {
      out.push({ path: `${path}/…`, file: new File([], "…") });
      return;
    }
    const reader = (entry as FileSystemDirectoryEntry).createReader();
    // readEntries returns at most ~100 entries per call - keep reading until empty.
    for (;;) {
      const batch = await new Promise<FileSystemEntry[]>((resolve, reject) => reader.readEntries(resolve, reject));
      if (batch.length === 0) break;
      await Promise.all(batch.map((child) => walk(child, path, out)));
    }
  }
}

export function entriesFromFileList(files: FileList): UploadEntry[] {
  return Array.from(files).map((file) => ({ path: file.webkitRelativePath || file.name, file }));
}
