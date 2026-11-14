// Short, practical fix guidance for the CWEs the bundled scanners report most.
// Deliberately brief - it points an engineer in the right direction and links out
// for depth, rather than trying to be a security textbook.

export interface Remediation {
  title: string;
  fix: string;
  example?: string;
  owasp?: { label: string; url: string };
}

const OWASP = "https://cheatsheetseries.owasp.org/cheatsheets";

export const REMEDIATION: Record<string, Remediation> = {
  "CWE-89": {
    title: "SQL injection",
    fix: "Never build SQL with f-strings, % or +. Pass user values as bound parameters so the driver keeps data separate from the query.",
    example: 'cursor.execute("SELECT * FROM todos WHERE title = ?", (title,))',
    owasp: { label: "Query Parameterization", url: `${OWASP}/Query_Parameterization_Cheat_Sheet.html` },
  },
  "CWE-78": {
    title: "OS command injection",
    fix: "Avoid shell=True and os.system. Call subprocess with an argument list so input is never parsed by a shell; validate against an allowlist where possible.",
    example: 'subprocess.run(["convert", src_path, dst_path], check=True)',
    owasp: { label: "OS Command Injection Defense", url: `${OWASP}/OS_Command_Injection_Defense_Cheat_Sheet.html` },
  },
  "CWE-79": {
    title: "Cross-site scripting",
    fix: "Let the template engine escape output. Don't mark user input as safe (|safe, Markup) and avoid building HTML by string concatenation.",
    owasp: { label: "XSS Prevention", url: `${OWASP}/Cross_Site_Scripting_Prevention_Cheat_Sheet.html` },
  },
  "CWE-22": {
    title: "Path traversal",
    fix: "Resolve the final path and verify it is still inside the intended base directory before opening it. Prefer IDs over user-supplied filenames.",
    example: "dest = (base / name).resolve()\nif not dest.is_relative_to(base.resolve()): abort(400)",
    owasp: { label: "Input Validation", url: `${OWASP}/Input_Validation_Cheat_Sheet.html` },
  },
  "CWE-502": {
    title: "Unsafe deserialization",
    fix: "Don't unpickle data that crosses a trust boundary. Use JSON (or a schema-validated format) for anything a user can influence.",
    owasp: { label: "Deserialization", url: `${OWASP}/Deserialization_Cheat_Sheet.html` },
  },
  "CWE-94": {
    title: "Code injection",
    fix: "Remove eval/exec on dynamic input. Parse data with a real parser (json, ast.literal_eval for literals) instead.",
    owasp: { label: "Injection Prevention", url: `${OWASP}/Injection_Prevention_Cheat_Sheet.html` },
  },
  "CWE-95": {
    title: "Eval injection",
    fix: "Remove eval/exec on dynamic input. Parse data with a real parser (json, ast.literal_eval for literals) instead.",
    owasp: { label: "Injection Prevention", url: `${OWASP}/Injection_Prevention_Cheat_Sheet.html` },
  },
  "CWE-327": {
    title: "Weak cryptography",
    fix: "Replace MD5/SHA1 for security purposes. Use hashlib.sha256 for integrity, and bcrypt/argon2 for passwords. If the hash isn't security-relevant, pass usedforsecurity=False.",
    owasp: { label: "Cryptographic Storage", url: `${OWASP}/Cryptographic_Storage_Cheat_Sheet.html` },
  },
  "CWE-328": {
    title: "Weak hash",
    fix: "Use SHA-256 or stronger for integrity, and a slow password hash (bcrypt, argon2) for credentials.",
    owasp: { label: "Password Storage", url: `${OWASP}/Password_Storage_Cheat_Sheet.html` },
  },
  "CWE-798": {
    title: "Hardcoded credentials",
    fix: "Move secrets to environment variables or a secrets manager, rotate the exposed value, and purge it from git history.",
    owasp: { label: "Secrets Management", url: `${OWASP}/Secrets_Management_Cheat_Sheet.html` },
  },
  "CWE-489": {
    title: "Debug mode in production",
    fix: "Drive debug from configuration (e.g. FLASK_DEBUG) and make sure it is off in deployed environments - the debugger allows code execution.",
  },
  "CWE-918": {
    title: "Server-side request forgery",
    fix: "Allowlist destination hosts, block internal address ranges after DNS resolution, and don't forward raw user URLs.",
    owasp: { label: "SSRF Prevention", url: `${OWASP}/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html` },
  },
  "CWE-611": {
    title: "XML external entities",
    fix: "Parse untrusted XML with defusedxml, or disable external entity resolution in the parser.",
    owasp: { label: "XXE Prevention", url: `${OWASP}/XML_External_Entity_Prevention_Cheat_Sheet.html` },
  },
  "CWE-352": {
    title: "Cross-site request forgery",
    fix: "Enable CSRF protection (Flask-WTF CSRFProtect, Django middleware) on state-changing routes.",
    owasp: { label: "CSRF Prevention", url: `${OWASP}/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html` },
  },
};

export function remediationFor(cwes: string[]): Remediation | undefined {
  for (const c of cwes) if (REMEDIATION[c]) return REMEDIATION[c];
  return undefined;
}

export function cweUrl(cwe: string): string {
  const n = cwe.replace(/^CWE-/, "");
  return `https://cwe.mitre.org/data/definitions/${n}.html`;
}

export function cweName(cwe: string): string {
  return REMEDIATION[cwe]?.title ?? cwe;
}
