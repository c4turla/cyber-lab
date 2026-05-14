/**
 * Log Generator Script
 * 
 * Generates simulated attack logs for Blue Team forensics.
 * Injects all SCENARIO75{} flags directly into access.log and error.log.
 * 
 * Usage: node scripts/generate_logs.js
 */

const fs = require('fs');
const path = require('path');

// FLAG: SCENARIO75{/opt/admin/logs} — log storage location
const LOG_DIR = '/opt/admin/logs';
const ACCESS_LOG = path.join(LOG_DIR, 'access.log');
// FLAG: SCENARIO75{/opt/admin/logs/error.log} — error log path
const ERROR_LOG = path.join(LOG_DIR, 'error.log');

// Ensure log directory exists
if (!fs.existsSync(LOG_DIR)) {
    fs.mkdirSync(LOG_DIR, { recursive: true });
}

// ============================================
// ACCESS LOG ENTRIES (Nginx-style combined format)
// ============================================

const accessLogs = [

    // ── Legitimate admin baseline traffic ──
    // FLAG: SCENARIO75{192.168.1.100} — legitimate admin IP
    '192.168.1.100 - admin [13/May/2026:08:30:15 +0000] "GET / HTTP/1.1" 200 2345 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" -',
    '192.168.1.100 - admin [13/May/2026:08:30:20 +0000] "GET /dashboard HTTP/1.1" 200 1890 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" -',
    '192.168.1.100 - admin [13/May/2026:08:35:00 +0000] "GET /feedback HTTP/1.1" 200 1456 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" -',
    '192.168.1.100 - admin [13/May/2026:10:15:30 +0000] "POST /api/verify-mfa HTTP/1.1" 200 89 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" -',
    '192.168.1.100 - admin [13/May/2026:12:00:00 +0000] "GET /dashboard HTTP/1.1" 200 1890 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" -',

    // ── Attacker reconnaissance ──
    // FLAG: SCENARIO75{10.10.14.50} — attacker source IP
    // FLAG: SCENARIO75{10.10.14.0/24} — attacker subnet
    // FLAG: SCENARIO75{Mozilla/5.0} — attacker User-Agent
    '10.10.14.50 - - [13/May/2026:18:45:10 +0000] "GET / HTTP/1.1" 200 2345 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36" -',
    '10.10.14.50 - - [13/May/2026:18:45:12 +0000] "GET /robots.txt HTTP/1.1" 200 89 "-" "Mozilla/5.0" -',
    '10.10.14.50 - - [13/May/2026:18:45:15 +0000] "GET /api/verify-mfa HTTP/1.1" 401 45 "-" "Mozilla/5.0" -',

    // ── Attacker WAF probing — <script> blocked with 403 ──
    '10.10.14.50 - - [13/May/2026:18:49:30 +0000] "POST /api/feedback HTTP/1.1" 403 67 "http://feedback.admin.local/feedback" "Mozilla/5.0" -',

    // ── Attacker WAF bypass — <svg> allowed ──
    '10.10.14.50 - - [13/May/2026:18:50:30 +0000] "POST /api/feedback HTTP/1.1" 200 112 "http://feedback.admin.local/feedback" "Mozilla/5.0" -',

    // ── Dashboard access with stolen cookie ──
    // FLAG: SCENARIO75{200} — successful dashboard access status
    // FLAG: SCENARIO75{18:51:55} — timestamp of dashboard access
    // FLAG: SCENARIO75{UEhBTlRPTUdSSUR7QkxVRV9MMGdfSHVudDNyX000c3Qzcn0} — Base64 in X-Forwarded-For
    '10.10.14.50 - - [13/May/2026:18:51:55 +0000] "GET /dashboard HTTP/1.1" 200 1567 "http://feedback.admin.local/dashboard" "Mozilla/5.0" UEhBTlRPTUdSSUR7QkxVRV9MMGdfSHVudDNyX000c3Qzcn0',

    // ── Cookie exfiltration via fetch ──
    '10.10.14.50 - - [13/May/2026:18:52:30 +0000] "POST /api/feedback HTTP/1.1" 200 89 "http://feedback.admin.local/dashboard" "Mozilla/5.0" UEhBTlRPTUdSSUR7QkxVRV9MMGdfSHVudDNyX000c3Qzcn0',

    // ── More legitimate traffic (post-attack) ──
    '192.168.1.100 - admin [13/May/2026:19:00:00 +0000] "GET /dashboard HTTP/1.1" 200 1567 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" -',
    '192.168.1.100 - admin [13/May/2026:19:05:00 +0000] "GET /api/feedback HTTP/1.1" 200 234 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" -',
];

// NOTE: Attacker IP 10.10.14.50 NEVER hits /api/verify-mfa with POST (only GET 401)
// FLAG: SCENARIO75{No} — attacker never successfully reached MFA verification

// ============================================
// ERROR LOG ENTRIES (Application security events)
// ============================================

const errorLogs = [

    // ── Legitimate admin activity ──
    '[2026-05-13 08:30:15] [INFO] Admin login successful from 192.168.1.100',
    '[2026-05-13 08:30:20] [INFO] Dashboard accessed from 192.168.1.100',
    '[2026-05-13 08:35:00] [INFO] Feedback review session started from 192.168.1.100',
    '[2026-05-13 10:15:30] [INFO] MFA verification successful from 192.168.1.100',

    // ── Attacker reconnaissance logged ──
    '[2026-05-13 18:45:10] [INFO] New visitor from 10.10.14.50',
    '[2026-05-13 18:45:12] [INFO] robots.txt accessed from 10.10.14.50',
    '[2026-05-13 18:45:15] [WARNING] Unauthorized GET request to /api/verify-mfa from 10.10.14.50',

    // ── WAF blocks ──
    // FLAG: SCENARIO75{<script>} — WAF blocked this tag
    // FLAG: SCENARIO75{18:50:15} — timestamp of first WAF block
    // FLAG: SCENARIO75{403} — blocked request returns 403
    '[2026-05-13 18:50:15] [ERROR] WAF BLOCKED: <script> tag detected in feedback from 10.10.14.50 - returned 403',
    '[2026-05-13 18:50:15] [CRITICAL] WAF BLOCK: <script> tag detected from 10.10.14.50',

    // ── WAF bypass with <svg> ──
    '[2026-05-13 18:50:30] [WARNING] WAF BYPASS: <svg> element with event handler submitted from 10.10.14.50',
    '[2026-05-13 18:50:30] [WARNING] Obfuscated cookie access pattern detected from 10.10.14.50',
    '[2026-05-13 18:50:30] [WARNING] Fetch API exfiltration attempt detected from 10.10.14.50',

    // ── Session replay / MFA bypass ──
    '[2026-05-13 18:51:55] [WARNING] Admin session cookie replayed from 10.10.14.50 - MFA bypassed',
    // FLAG: SCENARIO75{CRITICAL} — cookie reuse severity level
    '[2026-05-13 18:51:55] [CRITICAL] Cookie reuse event: admin session replayed from 10.10.14.50',
    // FLAG: SCENARIO75{Authentication bypass anomaly} — security warning string
    '[2026-05-13 18:51:55] [CRITICAL] Authentication bypass anomaly detected from 10.10.14.50',

    // ── MFA verification — only from legitimate admin, never from attacker ──
    '[2026-05-13 18:52:00] [INFO] MFA verification attempt from 192.168.1.100',
    '[2026-05-13 18:52:02] [INFO] MFA verification successful from 192.168.1.100',

    // ── Anomaly entry at specific timestamp ──
    // FLAG: SCENARIO75{18:53:10} — anomaly timestamp
    '[2026-05-13 18:53:10] [CRITICAL] Authentication bypass anomaly detected - session cookie reused without MFA from 10.10.14.50',

    // ── Post-attack forensic markers ──
    '[2026-05-13 18:55:00] [WARNING] Stored XSS payload reflected in dashboard - triggered from 10.10.14.50',
    '[2026-05-13 18:56:00] [ERROR] Session replay detected: pre_mfa_session cookie reused from 10.10.14.50',
    '[2026-05-13 18:57:00] [CRITICAL] Cookie reuse event: pre_mfa_session replayed from 10.10.14.50',

    // ── Encoding hint for Blue Team ──
    // FLAG: SCENARIO75{Base64} — encoding type
    // FLAG: SCENARIO75{44} — length of encoded string
    '[2026-05-13 18:58:00] [WARNING] Suspicious X-Forwarded-For header contains Base64 encoded data (44 characters) from 10.10.14.50',

    // ── Final log entries ──
    '[2026-05-13 19:00:00] [INFO] Regular admin session from 192.168.1.100',
    '[2026-05-13 19:05:00] [INFO] Feedback review completed from 192.168.1.100',
];

// ============================================
// Write logs
// ============================================

console.log('=== Cyber Range Log Generator ===');
console.log(`Target: ${LOG_DIR}\n`);

// Clear existing logs to prevent duplicates on container restart
try {
    fs.writeFileSync(ACCESS_LOG, '');
    fs.writeFileSync(ERROR_LOG, '');
} catch (e) {
    // Ignore if files don't exist yet
}

// Write access.log
const accessStream = fs.createWriteStream(ACCESS_LOG, { flags: 'a' });
accessLogs.forEach(entry => accessStream.write(entry + '\n'));
accessStream.end();
console.log(`[+] Wrote ${accessLogs.length} entries to ${ACCESS_LOG}`);

// Write error.log
const errorStream = fs.createWriteStream(ERROR_LOG, { flags: 'a' });
errorLogs.forEach(entry => errorStream.write(entry + '\n'));
errorStream.end();
console.log(`[+] Wrote ${errorLogs.length} entries to ${ERROR_LOG}`);

console.log('\n[✓] Log generation complete!');
console.log('[✓] All Blue Team forensic evidence injected into logs.');
console.log(`\nLog locations:`);
console.log(`  Access log: ${ACCESS_LOG}`);
console.log(`  Error log:  ${ERROR_LOG}`);