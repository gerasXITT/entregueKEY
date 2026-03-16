"use strict";

const http   = require("http");
const fs     = require("fs");
const path   = require("path");
const crypto = require("crypto");

// ── CONFIG ───────────────────────────────────────────────────────
const PORT        = process.env.PORT || 3000;
const ADMIN_TOKEN = process.env.ADMIN_TOKEN || "SIXSEVEN_ADMIN";

const DATA_DIR  = process.env.DATA_DIR || path.join("/tmp", "sixseven-data");
const KEYS_FILE = path.join(DATA_DIR, "keys.json");
const LOG_FILE  = path.join(DATA_DIR, "access.log");

try {
    if (!fs.existsSync(DATA_DIR))  fs.mkdirSync(DATA_DIR, { recursive: true });
    if (!fs.existsSync(KEYS_FILE)) fs.writeFileSync(KEYS_FILE, "[]", "utf8");
} catch (e) {
    console.error("Erro ao criar diretório de dados:", e.message);
}

// ── DURACOES ─────────────────────────────────────────────────────
const DURATION_MS = {
    daily  :  1 * 24 * 60 * 60 * 1000,
    weekly :  7 * 24 * 60 * 60 * 1000,
    monthly: 30 * 24 * 60 * 60 * 1000,
    forever: null,
};

// ── DB ───────────────────────────────────────────────────────────
function dbLoad() {
    try { return JSON.parse(fs.readFileSync(KEYS_FILE, "utf8")); }
    catch (_) { return []; }
}

// FIX: dbSave com try/catch — antes crashava silenciosamente se /tmp cheio
function dbSave(db) {
    try {
        fs.writeFileSync(KEYS_FILE, JSON.stringify(db, null, 2), "utf8");
    } catch (e) {
        console.error("ERRO ao salvar keys.json:", e.message);
        throw new Error("Falha ao persistir dados: " + e.message);
    }
}

function dbFind(db, key) {
    const norm = (key || "").toUpperCase().trim();
    return db.find(r => r.key === norm) || null;
}

// ── LOG ──────────────────────────────────────────────────────────
function writeLog(msg) {
    const line = "[" + new Date().toISOString() + "] " + msg + "\n";
    try { fs.appendFileSync(LOG_FILE, line, "utf8"); } catch (_) {}
    process.stdout.write(line);
}

// ── GERACAO ──────────────────────────────────────────────────────
const CHARSET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
function randomSegment(len) {
    len = len || 8;
    let r = "";
    while (r.length < len) {
        const b = crypto.randomBytes(len * 4);
        for (let i = 0; i < b.length && r.length < len; i++) {
            const max = Math.floor(256 / CHARSET.length) * CHARSET.length;
            if (b[i] < max) r += CHARSET[b[i] % CHARSET.length];
        }
    }
    return r;
}

function generateKeys(count, type) {
    count = Math.min(Math.max(parseInt(count) || 1, 1), 500);
    type  = Object.prototype.hasOwnProperty.call(DURATION_MS, type) ? type : "forever";

    const db       = dbLoad();
    const existing = new Set(db.map(r => r.key));
    const now      = new Date();
    const expiresAt = DURATION_MS[type]
        ? new Date(now.getTime() + DURATION_MS[type]).toISOString()
        : null;

    const created = [];
    let tries = 0;
    while (created.length < count && tries < count * 500) {
        tries++;
        const key = "SIXSEVEN-" + randomSegment(8) + "-" + randomSegment(8);
        if (existing.has(key)) continue;
        existing.add(key);
        const rec = {
            key, type,
            createdAt: now.toISOString(), expiresAt,
            hwid: null, device: null, hwidBoundAt: null, lastSeen: null, revoked: false,
        };
        db.push(rec);
        created.push(rec);
    }
    dbSave(db);
    return created;
}

// ── VALIDACAO ────────────────────────────────────────────────────
function validate(rawKey, hwid, device) {
    const key   = (rawKey || "").toUpperCase().trim();
    const hNorm = (hwid   || "").toUpperCase().trim();

    // FIX: validação de key vazia antes de qualquer operação
    if (!key || key.length < 6) {
        return { ok: false, reason: "key nao informada", action: "invalid" };
    }

    const db  = dbLoad();
    const rec = dbFind(db, key);

    if (!rec)        { writeLog("INVALID  key=" + key); return { ok: false, reason: "key invalida",  action: "invalid" }; }
    if (rec.revoked) { writeLog("REVOKED  key=" + key); return { ok: false, reason: "key revogada",  action: "revoked" }; }

    if (rec.expiresAt && new Date() > new Date(rec.expiresAt)) {
        writeLog("EXPIRED  key=" + key);
        return { ok: false, reason: "key expirada em " + rec.expiresAt.substring(0, 10), action: "expired", expiresAt: rec.expiresAt };
    }

    if (!hNorm || hNorm.length < 4) {
        writeLog("NO_HWID  key=" + key);
        return { ok: false, reason: "hwid nao enviado", action: "no_hwid" };
    }

    if (!rec.hwid) {
        rec.hwid        = hNorm;
        rec.device      = device || "desconhecido";
        rec.hwidBoundAt = new Date().toISOString();
        rec.lastSeen    = new Date().toISOString();
        dbSave(db);
        writeLog("BOUND    key=" + key + "  hwid=" + hNorm);
        return { ok: true, reason: "key valida — hwid registrado", action: "bound", type: rec.type, expiresAt: rec.expiresAt };
    }

    if (rec.hwid !== hNorm) {
        writeLog("MISMATCH key=" + key + "  got=" + hNorm);
        return { ok: false, reason: "dispositivo nao autorizado", action: "mismatch" };
    }

    rec.lastSeen = new Date().toISOString();
    dbSave(db);
    writeLog("OK       key=" + key);
    return { ok: true, reason: "key valida", action: "verified", type: rec.type, expiresAt: rec.expiresAt };
}

// ── ADMIN ────────────────────────────────────────────────────────
function revokeKey(key) {
    const db  = dbLoad();
    const rec = dbFind(db, key);
    if (!rec)        return { done: false, reason: "key nao encontrada" };
    // FIX: antes retornava false genérico se já revogada
    if (rec.revoked) return { done: false, reason: "key ja estava revogada" };
    rec.revoked = true;
    dbSave(db);
    writeLog("REVOKE   key=" + rec.key);
    return { done: true, reason: "key revogada" };
}

// FIX: nova função — antes era impossível desrevogar pela API/painel
function unrevokeKey(key) {
    const db  = dbLoad();
    const rec = dbFind(db, key);
    if (!rec)         return { done: false, reason: "key nao encontrada" };
    if (!rec.revoked) return { done: false, reason: "key nao estava revogada" };
    rec.revoked = false;
    dbSave(db);
    writeLog("UNREVOKE key=" + rec.key);
    return { done: true, reason: "key restaurada" };
}

function resetHwid(key) {
    const db  = dbLoad();
    const rec = dbFind(db, key);
    if (!rec)    return { done: false, reason: "key nao encontrada" };
    // FIX: antes retornava false causando 404 confuso quando sem hwid
    if (!rec.hwid) return { done: false, reason: "key nao tem hwid vinculado" };
    rec.hwid        = null;
    rec.device      = null;
    rec.hwidBoundAt = null;
    dbSave(db);
    writeLog("HWID_RESET key=" + rec.key);
    return { done: true, reason: "hwid resetado" };
}

function listKeys(filter) {
    const db  = dbLoad();
    const now = new Date();
    return db.filter(r => {
        if (filter === "active")  return !r.revoked && (!r.expiresAt || new Date(r.expiresAt) > now);
        if (filter === "expired") return !r.revoked && r.expiresAt && new Date(r.expiresAt) <= now;
        if (filter === "revoked") return r.revoked;
        return true;
    }).map(r => ({
        ...r,
        expired: r.expiresAt ? new Date(r.expiresAt) <= now : false,
    }));
}

function getStats() {
    const db  = dbLoad();
    const now = new Date();
    const byType = { daily: 0, weekly: 0, monthly: 0, forever: 0 };
    db.forEach(r => { if (byType[r.type] !== undefined) byType[r.type]++; });
    return {
        total   : db.length,
        active  : db.filter(r => !r.revoked && (!r.expiresAt || new Date(r.expiresAt) > now)).length,
        expired : db.filter(r => !r.revoked && r.expiresAt && new Date(r.expiresAt) <= now).length,
        revoked : db.filter(r => r.revoked).length,
        withHwid: db.filter(r => r.hwid).length,
        byType,
    };
}

// ── HTTP SERVER ──────────────────────────────────────────────────
const server = http.createServer((req, res) => {
    // FIX: parse de URL com try/catch — antes quebrava com URLs malformadas
    let url;
    try {
        url = new URL(req.url, "http://localhost");
    } catch (_) {
        res.statusCode = 400;
        res.setHeader("Content-Type", "application/json");
        res.end(JSON.stringify({ ok: false, reason: "url malformada" }));
        return;
    }

    const route = url.pathname.replace(/\/$/, "") || "/";
    const p     = url.searchParams;

    res.setHeader("Content-Type", "application/json");
    res.setHeader("Access-Control-Allow-Origin", "*");

    // FIX: CORS preflight agora inclui POST e cabeçalhos corretos
    if (req.method === "OPTIONS") {
        res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
        res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
        res.statusCode = 204;
        res.end();
        return;
    }

    const send    = (code, obj) => { res.statusCode = code; res.end(JSON.stringify(obj)); };
    const adminOk = () => {
        if ((p.get("token") || "") !== ADMIN_TOKEN) {
            send(401, { ok: false, reason: "token invalido" });
            return false;
        }
        return true;
    };

    if (route === "/")
        return send(200, { ok: true, service: "Six Painel KeySystem", version: "4.0" });

    // ── /admin (painel HTML) ─────────────────────────────────────
    if (route === "/admin") {
        const htmlFile = path.join(__dirname, "admin.html");
        if (!fs.existsSync(htmlFile)) {
            res.setHeader("Content-Type", "text/plain");
            res.statusCode = 404;
            return res.end("admin.html nao encontrado");
        }
        res.setHeader("Content-Type", "text/html; charset=utf-8");
        res.statusCode = 200;
        return res.end(fs.readFileSync(htmlFile, "utf8"));
    }

    if (route === "/validate") {
        const result = validate(p.get("key") || "", p.get("hwid") || "", p.get("device") || "");
        return send(result.ok ? 200 : 403, result);
    }

    if (route === "/admin/generate") {
        if (!adminOk()) return;
        const type = p.get("type") || "forever";
        if (!Object.prototype.hasOwnProperty.call(DURATION_MS, type))
            return send(400, { ok: false, reason: "type invalido. Use: daily, weekly, monthly, forever" });
        const keys = generateKeys(p.get("n") || "1", type);
        return send(200, {
            ok: true,
            generated: keys.length,
            type,
            expiresAt: keys[0] ? keys[0].expiresAt : null,
            keys: keys.map(r => r.key),
        });
    }

    if (route === "/admin/list") {
        if (!adminOk()) return;
        const list = listKeys(p.get("filter") || "all");
        return send(200, { ok: true, count: list.length, keys: list });
    }

    if (route === "/admin/revoke") {
        if (!adminOk()) return;
        const result = revokeKey(p.get("key") || "");
        return send(result.done ? 200 : 404, { ok: result.done, reason: result.reason });
    }

    // FIX: nova rota /admin/unrevoke — antes não existia
    if (route === "/admin/unrevoke") {
        if (!adminOk()) return;
        const result = unrevokeKey(p.get("key") || "");
        return send(result.done ? 200 : 404, { ok: result.done, reason: result.reason });
    }

    if (route === "/admin/reset-hwid") {
        if (!adminOk()) return;
        const result = resetHwid(p.get("key") || "");
        return send(result.done ? 200 : 404, { ok: result.done, reason: result.reason });
    }

    if (route === "/admin/stats") {
        if (!adminOk()) return;
        return send(200, { ok: true, stats: getStats() });
    }

    if (route === "/admin/log") {
        if (!adminOk()) return;
        res.setHeader("Content-Type", "text/plain");
        res.statusCode = 200;
        if (fs.existsSync(LOG_FILE)) {
            const lines = fs.readFileSync(LOG_FILE, "utf8")
                .split(/\r?\n/).filter(Boolean).slice(-300).reverse();
            return res.end(lines.join("\n"));
        }
        return res.end("sem logs ainda.");
    }

    send(404, { ok: false, reason: "rota nao encontrada" });
});

server.listen(PORT, "0.0.0.0", () => {
    console.log("================================================");
    console.log("  Six Painel v4  |  KEY SYSTEM SERVER");
    console.log("================================================");
    console.log("  Porta      : " + PORT);
    console.log("  Dados      : " + DATA_DIR);
    console.log("  Admin token: (via env ADMIN_TOKEN ou SIXSEVEN_ADMIN)");
    console.log("================================================");
});

server.on("error", err => {
    console.error("ERRO SERVIDOR: " + err.message);
    process.exit(1);
});
