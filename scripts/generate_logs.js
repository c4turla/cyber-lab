/**
 * Log Generator Script
 * 
 * Generates simulated attack logs for Blue Team forensics.
 * Run this script after the server starts to inject realistic telemetry.
 * 
 * Usage: node scripts/generate_logs.js
 */

const fs = require('fs');
const path = require('path');

const LOG_DIR = '/opt/admin/logs';
const ACCESS_LOG = path.join(LOG_DIR, 'access.log');
const ERROR_LOG = path.join(LOG_DIR, 'error.log');

// Ensure log directory exists
if (!fs.existsSync(LOG_DIR)) {
    fs.mkdirSync(LOG_DIR, { recursive: true });
}

function writeAccessLog(entries) {
    const stream = fs.createWriteStream(ACCESS_LOG, { flags: 'a' });
    entries.forEach(entry => stream.write(entry + '\n'));
    stream.end();
    console.log(`[+] Wrote ${entries.length} entries to ${ACCESS_LOG}`);
}

function writeErrorLog(entries) {
    const stream = fs.createWriteStream(ERROR_LOG, { flags: 'a' });
    entries.forEach(entry => stream.write(entry + '\n'));
    stream.end();
    console.log(`[+] Wrote ${entries.length} entries to ${ERROR_LOG}`);
}

// ============================================
// Blue Team Logs Generation
// ============================================

// PHASE 1: Log Forensics
// - Attacker from 10.10.14.50 with Mozilla/5.0
// - Dashboard access at 18:51:55 (200 status)
// - X-Forwarded-For with Base64 encoded string

const accessLogs = [
    // Legitimate admin traffic from 192.168.1.100 (FLAG: SCENARIO75{192.168.1.100})
    '192.168.1.100 - - [13/May/2026:08:30:15 +0000] "GET / HTTP/1.1" 200 2345 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" -',
    '192.168.1.100 - - [13/May/2026:08:30:20 +0000] "GET /dashboard HTTP/1.1" 200 1890 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" -',
    '192.168.1.100 - - [13/May/2026:08:35:00 +0000] "GET /feedback HTTP/1.1" 200 1456 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" -',
    
    // Attacker reconnaissance - 10.10.14.50 (FLAG: SCENARIO75{10.10.14.50})
    // Subnet 10.10.14.0/24 (FLAG: SCENARIO75{10.10.14.0/24})
    '10.10.14.50 - - [13/May/2026:18:45:10 +0000] "GET / HTTP/1.1" 200 2345 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36" -',
    '10.10.14.50 - - [13/May/2026:18:45:12 +0000] "GET /robots.txt HTTP/1.1" 200 89 "-" "Mozilla/5.0" -',
    '10.10.14.50 - - [13/May/2026:18:45:15 +0000] "GET /api/verify-mfa HTTP/1.1" 401 45 "-" "Mozilla/5.0" -',
    
    // Attacker probes WAF - tries <script> tag
    '10.10.14.50 - - [13/May/2026:18:49:30 +0000] "POST /api/feedback HTTP/1.1" 403 67 "http://feedback.admin.local/feedback" "Mozilla/5.0" -',
    
    // Attacker bypasses WAF with <svg onload>
    '10.10.14.50 - - [13/May/2026:18:50:30 +0000] "POST /api/feedback HTTP/1.1" 200 112 "http://feedback.admin.local/feedback" "Mozilla/5.0" -',
    
    // Attacker accesses dashboard with stolen cookie - 200 at 18:51:55 (FLAGS)
    // Status: 200 (FLAG: SCENARIO75{200})
    // Timestamp: 18:51:55 (FLAG: SCENARIO75{18:51:55})
    '10.10.14.50 - - [13/May/2026:18:51:55 +0000] "GET /dashboard HTTP/1.1" 200 1567 "http://feedback.admin.local/dashboard" "Mozilla/5.0" UEhBTlRPTUdSSUR7QkxVRV9MMGdfSHVudDNyX000c3Qzcn0=',
    
    // Attacker exfiltrates data with X-Forwarded-For containing Base64
    // Base64: UEhBTlRPTUdSSUR7QkxVRV9MMGdfSHVudDNyX000c3Qzcn0= (FLAG)
    '10.10.14.50 - - [13/May/2026:18:52:30 +0000] "POST /api/feedback HTTP/1.1" 200 89 "http://feedback.admin.local/dashboard" "Mozilla/5.0" UEhBTlRPTUdSSUR7QkxVRV9MMGdfSHVudDNyX000c3Qzcn0=',
    
    // Additional background traffic
    '192.168.1.100 - - [13/May/2026:19:00:00 +0000] "GET /dashboard HTTP/1.1" 200 1567 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" -',
];

// PHASE 2 & 3: Error logs for WAF alerts and anomalies
const errorLogs = [
    // WAF block at 18:50:15 (FLAG: SCENARIO75{18:50:15})
    // First WAF block for <script> tag (FLAG: SCENARIO75{<script>})
    '[2026-05-13 18:50:15] [ERROR] WAF BLOCKED <script> from 10.10.14.50',
    '[2026-05-13 18:50:15] [CRITICAL] WAF BLOCK: <script> tag detected from 10.10.14.50',
    
    // WAF bypass detected
    '[2026-05-13 18:50:30] [WARNING] WAF BYPASS attempt with <svg> from 10.10.14.50',
    '[2026-05-13 18:50:30] [WARNING] Obfuscated cookie access detected from 10.10.14.50',
    '[2026-05-13 18:50:30] [WARNING] Fetch API exfiltration attempt from 10.10.14.50',
    
    // Dashboard access with session replay - authentication bypass
    // CRITICAL log level (FLAG: SCENARIO75{CRITICAL})
    // Authentication bypass anomaly (FLAG: SCENARIO75{Authentication bypass anomaly})
    '[2026-05-13 18:51:55] [WARNING] Admin session detected for 10.10.14.50 - MFA bypassed',
    '[2026-05-13 18:51:55] [CRITICAL] Authentication bypass anomaly at 2026-05-13 18:51:55',
    
    // MFA verification never reached by attacker
    '[2026-05-13 18:52:00] [WARNING] MFA verification attempt from 192.168.1.100',
    '[2026-05-13 18:52:02] [WARNING] MFA success for 192.168.1.100',
    
    // Anomaly timestamp at 18:53:10 (FLAG: SCENARIO75{18:53:10})
    '[2026-05-13 18:53:10] [CRITICAL] Authentication bypass anomaly at 2026-05-13 18:53:10',
    
    // Additional log entries for context
    '[2026-05-13 18:55:00] [WARNING] Feedback submitted from 10.10.14.50: XSS payload reflected in dashboard',
    '[2026-05-13 18:56:00] [ERROR] Session replay detected: pre_mfa_session reused from 10.10.14.50',
    
    // Cookie reuse flagged as CRITICAL
    '[2026-05-13 18:57:00] [CRITICAL] Cookie reuse event: pre_mfa_session replayed from 10.10.14.50',
    
    // Legitimate admin log entries
    '[2026-05-13 08:30:15] [INFO] Admin login successful from 192.168.1.100',
    '[2026-05-13 08:30:20] [INFO] Dashboard accessed from 192.168.1.100',
    '[2026-05-13 08:35:00] [INFO] Feedback review session started from 192.168.1.100',
];

console.log('=== Cyber Range Log Generator ===');
console.log(`Target: ${LOG_DIR}\n`);

// Clear existing logs (optional - keeping append behavior)
// fs.writeFileSync(ACCESS_LOG, '');
// fs.writeFileSync(ERROR_LOG, '');

writeAccessLog(accessLogs);
writeErrorLog(errorLogs);

console.log('\n[✓] Log generation complete!');
console.log('[✓] Blue Team forensic evidence injected.');
console.log('\nLog locations:');
console.log(`  Access log: ${ACCESS_LOG}`);
console.log(`  Error log:  ${ERROR_LOG}`);
console.log('\n=== Summary of Injected Evidence ===');
console.log('Attacker IP: 10.10.14.50 (SCENARIO75{10.10.14.50})');
console.log('Legitimate Admin: 192.168.1.100 (SCENARIO75{192.168.1.100})');
console.log('Dashboard access @18:51:55 - 200 (SCENARIO75{18:51:55}, SCENARIO75{200})');
console.log('WAF block @18:50:15 for <script> (SCENARIO75{18:50:15}, SCENARIO75{<script>})');
console.log('Authentication bypass anomaly @18:53:10 (SCENARIO75{18:53:10})');
console.log('Base64 encoded string in X-Forwarded-For');
console.log('Subnet: 10.10.14.0/24 (SCENARIO75{10.10.14.0/24})');