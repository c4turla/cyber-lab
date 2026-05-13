const express = require('express');
const cookieParser = require('cookie-parser');
const morgan = require('morgan');
const fs = require('fs');
const path = require('path');
const app = express();

// ============================================
// In-memory feedback storage
// FLAG: SCENARIO75{feedback_store}
// ============================================
let feedbackStore = [];
const MAX_FEEDBACK_STORE = 100;

const PORT = 3075;
const LOG_DIR = '/opt/admin/logs';

// Ensure log directory exists
if (!fs.existsSync(LOG_DIR)) {
    fs.mkdirSync(LOG_DIR, { recursive: true });
}

// Combined log format for Nginx-style logging
const LOG_FORMAT = ':remote-addr - :remote-user [:date[clf]] ":method :url HTTP/:http-version" :status :res[content-length] ":referrer" ":user-agent" :req[x-forwarded-for]';

// Create write streams for logs
const accessLogStream = fs.createWriteStream(path.join(LOG_DIR, 'access.log'), { flags: 'a' });
const errorLogStream = fs.createWriteStream(path.join(LOG_DIR, 'error.log'), { flags: 'a' });

// Setup morgan for access logs
app.use(morgan(LOG_FORMAT, { stream: accessLogStream }));

// Also log to error.log for specific events
function logError(msg) {
    const timestamp = new Date().toISOString().replace('T', ' ').substring(0, 19);
    const entry = `[${timestamp}] [ERROR] ${msg}\n`;
    errorLogStream.write(entry);
    console.error(msg);
}

function logWarning(msg) {
    const timestamp = new Date().toISOString().replace('T', ' ').substring(0, 19);
    const entry = `[${timestamp}] [WARNING] ${msg}\n`;
    errorLogStream.write(entry);
}

function logCritical(msg) {
    const timestamp = new Date().toISOString().replace('T', ' ').substring(0, 19);
    const entry = `[${timestamp}] [CRITICAL] ${msg}\n`;
    errorLogStream.write(entry);
    console.error(`CRITICAL: ${msg}`);
}

// Middleware
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(cookieParser());
app.use(express.static('public'));

// Set view engine
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// ============================================
// PHASE 1: Reconnaissance - Headers & Clues
// ============================================

// X-Powered-By header exposing Node.js (FLAG: SCENARIO75{Node.js})
app.use((req, res, next) => {
    res.setHeader('X-Powered-By', 'SCENARIO75{Node.js}');
    res.setHeader('X-Framework', 'Express');
    res.setHeader('X-Server', 'CyberRange-Lab');
    next();
});

// ============================================
// Serve robots.txt
// ============================================
app.get('/robots.txt', (req, res) => {
    res.type('text/plain');
    res.send(`User-agent: *
Disallow: /api/verify-mfa
Disallow: /dashboard
Disallow: /admin
`);
});

// ============================================
// Pre-authentication session cookie on first visit
// ============================================
app.use((req, res, next) => {
    if (!req.cookies.pre_mfa_session) {
        // FLAG: SCENARIO75{pre_mfa_session} - cookie name
        // FLAG: SCENARIO75{pending_mfa_verification} - cookie value
        // HttpOnly set to False intentionally (FLAG: SCENARIO75{False})
        res.cookie('pre_mfa_session', 'pending_mfa_verification', {
            httpOnly: false,
            secure: false,
            sameSite: 'Lax',
            path: '/'
        });
    }
    next();
});

// ============================================
// Routes
// ============================================

// Home page
app.get('/', (req, res) => {
    res.render('index', {
        title: 'Admin Feedback System',
        pre_mfa: req.cookies.pre_mfa_session || 'not set'
    });
});

// ============================================
// Feedback form page (GET)
// ============================================
app.get('/feedback', (req, res) => {
    res.render('feedback', { title: 'Submit Feedback' });
});

// ============================================
// PHASE 2: Defense Evasion (WAF & XSS)
// Feedback endpoint - POST only (FLAG: SCENARIO75{POST})
// ============================================
app.post('/api/feedback', (req, res) => {
    let { feedback } = req.body;
    const ip = req.ip || req.connection.remoteAddress;
    const ua = req.headers['user-agent'] || 'Unknown';

    // Validate feedback is not empty
    if (!feedback || feedback.trim() === '') {
        logError(`Empty feedback rejected from ${ip}`);
        return res.status(400).json({
            success: false,
            error: 'Feedback cannot be empty. Please provide your feedback.'
        });
    }

    // WAF Implementation - Blocks standard <script> tags
    // FLAG: SCENARIO75{403} - blocked request returns 403
    if (feedback && feedback.includes('<script>')) {
        logError(`WAF BLOCKED <script> from ${ip} at ${new Date().toISOString()}`);
        logCritical(`WAF BLOCK: <script> tag detected from ${ip}`);
        return res.status(403).json({
            error: 'WAF: Malicious content detected and blocked.',
            code: 403
        });
    }

    // WAF blocks direct document.cookie keyword access
    // Forces attacker to use bracket notation: window['docu'+'ment']['coo'+'kie']
    // (FLAG: SCENARIO75{window['docu'+'ment']['coo'+'kie']})
    if (feedback && feedback.includes('document.cookie')) {
        logError(`WAF BLOCKED document.cookie access from ${ip}`);
        logCritical(`WAF BLOCK: document.cookie keyword detected from ${ip}`);
        return res.status(403).json({
            error: 'WAF: Suspicious cookie access pattern detected and blocked.',
            code: 403
        });
    }

    // WAF Bypass - HTML5 <svg> with onload is allowed (FLAG: SCENARIO75{<svg>})
    // The WAF blocks standard <script> but allows <svg onload=...>
    if (feedback && feedback.includes('<svg')) {
        logWarning(`WAF BYPASS attempt with <svg> from ${ip}`);
    }

    // Obfuscation detection - window['docu'+'ment']['coo'+'kie']
    if (feedback && feedback.includes("window['docu'+'ment']['coo'+'kie']")) {
        logWarning(`Obfuscated cookie access detected from ${ip}`);
    }

    // Check for fetch API usage (FLAG: SCENARIO75{fetch})
    if (feedback && feedback.includes('fetch(')) {
        logWarning(`Fetch API exfiltration attempt from ${ip}`);
    }

    // Store feedback in memory (FLAG: SCENARIO75{feedback_store})
    const feedbackEntry = {
        id: feedbackStore.length + 1,
        content: feedback,
        ip: ip,
        userAgent: ua,
        timestamp: new Date().toISOString()
    };
    feedbackStore.push(feedbackEntry);
    
    // Keep store bounded
    if (feedbackStore.length > MAX_FEEDBACK_STORE) {
        feedbackStore = feedbackStore.slice(-MAX_FEEDBACK_STORE);
    }

    // Log the successful feedback to error.log
    logWarning(`Feedback submitted from ${ip}: ${feedback.substring(0, 100)}`);

    res.json({
        success: true,
        message: 'Feedback submitted successfully! An admin will review it shortly.',
        feedback: feedback
    });
});

// GET /api/feedback - Returns stored feedback list (admin only)
// FLAG: SCENARIO75{GET_feedback_api}
app.get('/api/feedback', (req, res) => {
    // Return a sanitized list (no IPs exposed for non-admin)
    const sanitized = feedbackStore.map(f => ({
        id: f.id,
        content: f.content,
        timestamp: f.timestamp
    }));
    res.json({
        total: feedbackStore.length,
        feedbacks: sanitized
    });
});

// ============================================
// MFA Verification endpoint (disallowed in robots.txt)
// FLAG: SCENARIO75{/api/verify-mfa}
// ============================================
app.post('/api/verify-mfa', (req, res) => {
    const { code } = req.body;
    const ip = req.ip || req.connection.remoteAddress;
    logWarning(`MFA verification attempt from ${ip}`);

    // Check if user already has an admin session - skip MFA
    if (req.cookies && req.cookies.adm_sess) {
        // FLAG: SCENARIO75{adm_sess} - admin session prefix
        logWarning(`MFA SKIPPED - User already has admin session from ${ip}`);
        logCritical(`Authentication bypass anomaly at ${new Date().toISOString()}`);
        return res.json({
            success: true,
            message: 'Already authenticated. MFA bypassed.',
            mfa_skipped: true
        });
    }

    if (code === '123456') {
        logWarning(`MFA success for ${ip}`);
        // FLAG: SCENARIO75{adm_sess} - admin session prefix
        res.cookie('adm_sess', 'adm_sess_authenticated_admin_' + Date.now(), {
            httpOnly: false,
            secure: false,
            path: '/'
        });
        return res.json({
            success: true,
            message: 'MFA verified successfully. Welcome back!'
        });
    }

    logError(`MFA failed for ${ip}: invalid code`);
    return res.status(401).json({
        success: false,
        message: 'Invalid MFA code.'
    });
});

// ============================================
// Dashboard - Admin area (FLAG: SCENARIO75{/dashboard})
// MFA Bypass via Session Replay
// ============================================

// Store dashboard access time for logging
app.all('/dashboard', (req, res) => {
    const now = new Date();
    const timeStr = now.toTimeString().split(' ')[0];
    const ip = req.ip || req.connection.remoteAddress;

    // Check for pre_mfa_session cookie
    const preMFACookie = req.cookies.pre_mfa_session;
    const admSession = req.cookies.adm_sess;

    // PHASE 3: MFA Bypass logic
    // If admin session cookie exists, skip MFA verification
    // FLAG: SCENARIO75{/api/verify-mfa} - the endpoint that gets bypassed
    let mfaBypassed = false;
    if (admSession && admSession.startsWith('adm_sess_')) {
        // FLAG: SCENARIO75{adm_sess} - session prefix confirmed
        // FLAG: SCENARIO75{/api/verify-mfa} - MFA verification completely skipped
        mfaBypassed = true;
        logCritical(`Authentication bypass anomaly at ${new Date().toISOString()}`);
        logWarning(`Admin session detected for ${ip} - MFA bypassed`);
    }

    // Check if this is a replay attack (has pre_mfa_session but no proper admin session)
    const isReplayAttack = preMFACookie && !admSession;

    // Determine if user is "authenticated" for dashboard access
    const isAuthenticated = !!admSession;

    if (isAuthenticated) {
        // Successful dashboard access - Log 200 status
        logWarning(`Dashboard access from ${ip} - Status: 200`);

        // XSS Payload reflection in xss-payload class (FLAG: SCENARIO75{xss-payload})
        // Stored XSS: feedback content rendered raw in dashboard
        const xssPayload = req.query.payload || req.body.payload || '';
        const reflectedPayload = xssPayload ? `<span class="xss-payload">${xssPayload}</span>` : '';

        res.render('dashboard', {
            title: 'Admin Dashboard - Feedback System',
            admSession: admSession,
            mfaBypassed: mfaBypassed,
            reflectedPayload: reflectedPayload,
            feedbackStore: feedbackStore,
            // Final Red Team Flag
            // FLAG: SCENARIO75{RED_C00k13_MFA_Byp4ss_0wn3d}
            finalFlag: 'SCENARIO75{RED_C00k13_MFA_Byp4ss_0wn3d}'
        });
    } else {
        // User needs MFA
        logWarning(`Unauthenticated dashboard access attempt from ${ip}`);
        res.redirect('/mfa');
    }
});

// ============================================
// MFA page
// ============================================
app.get('/mfa', (req, res) => {
    res.render('mfa', { title: 'MFA Verification' });
});

// ============================================
// API to check session status (for debugging flags)
// ============================================
app.get('/api/session-status', (req, res) => {
    res.json({
        pre_mfa_session: req.cookies.pre_mfa_session || 'not set',
        adm_sess: req.cookies.adm_sess || 'not set',
        has_pre_mfa: !!req.cookies.pre_mfa_session,
        has_adm_sess: !!req.cookies.adm_sess
    });
});

// ============================================
// Start server
// ============================================
app.listen(PORT, '0.0.0.0', () => {
    console.log(`=== Cyber Range: Admin Feedback System ===`);
    console.log(`Server running on port ${PORT}`);
    console.log(`Access: http://localhost:${PORT}`);
    console.log(`Logs: ${LOG_DIR}`);
    console.log(`========================================`);
});