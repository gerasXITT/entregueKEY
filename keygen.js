"use strict";

// ================================================================
//  Six Painel v4  |  KEY GENERATOR  —  CLI local
//
//  Uso:
//    node keygen.js                       → 1 key forever
//    node keygen.js 10 daily              → 10 keys (1 dia)
//    node keygen.js 10 weekly             → 10 keys (7 dias)
//    node keygen.js 10 monthly            → 10 keys (30 dias)
//    node keygen.js 10 forever            → 10 keys vitalícias
//    node keygen.js --list                → lista todas
//    node keygen.js --list active         → lista ativas
//    node keygen.js --list expired        → lista expiradas
//    node keygen.js --list revoked        → lista revogadas
//    node keygen.js --stats               → estatisticas
//    node keygen.js --revoke SIXSEVEN-XXX    → revoga key
//    node keygen.js --reset-hwid SIXSEVEN-XX → reseta HWID
//    node keygen.js --clear               → apaga tudo
//    node keygen.js --help
// ================================================================

const fs     = require("fs");
const path   = require("path");
const crypto = require("crypto");

const DATA_DIR  = path.join(__dirname, "data");
const KEYS_FILE = path.join(DATA_DIR,  "keys.json");

if (!fs.existsSync(DATA_DIR))  fs.mkdirSync(DATA_DIR, { recursive: true });
if (!fs.existsSync(KEYS_FILE)) fs.writeFileSync(KEYS_FILE, "[]", "utf8");

// ── CORES ────────────────────────────────────────────────────────
const C = {
    r: "\x1b[0m", b: "\x1b[1m", d: "\x1b[2m",
    G: "\x1b[32m", R: "\x1b[31m", Y: "\x1b[33m",
    C: "\x1b[36m", M: "\x1b[35m", g: "\x1b[90m",
};
const s = (c, t) => C[c] + t + C.r;

// ── DURACOES ─────────────────────────────────────────────────────
const DURATION_MS = {
    daily  :  1 * 24 * 60 * 60 * 1000,
    weekly :  7 * 24 * 60 * 60 * 1000,
    monthly: 30 * 24 * 60 * 60 * 1000,
    forever: null,
};

const TYPE_COL = { daily: "Y", weekly: "C", monthly: "M", forever: "G" };
const TYPE_LBL = { daily: "DIARIA  ", weekly: "SEMANAL ", monthly: "MENSAL  ", forever: "VITALIC." };

// ── DB ───────────────────────────────────────────────────────────
function dbLoad() {
    try { return JSON.parse(fs.readFileSync(KEYS_FILE, "utf8")); }
    catch (_) { return []; }
}
function dbSave(db) { fs.writeFileSync(KEYS_FILE, JSON.stringify(db, null, 2), "utf8"); }
function dbFind(db, key) {
    return db.find(r => r.key === (key || "").toUpperCase().trim()) || null;
}

// ── GERACAO ──────────────────────────────────────────────────────
const CHARSET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";

function randomSeg(len) {
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
    type  = DURATION_MS.hasOwnProperty(type) ? type : "forever";

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
        const key = "SIXSEVEN-" + randomSeg(8) + "-" + randomSeg(8);
        if (existing.has(key)) continue;
        existing.add(key);
        const rec = { key, type, createdAt: now.toISOString(), expiresAt,
                      hwid: null, device: null, hwidBoundAt: null, lastSeen: null, revoked: false };
        db.push(rec); created.push(rec);
    }
    dbSave(db);
    return created;
}

// ── HELPERS ──────────────────────────────────────────────────────
function isExpired(rec) { return rec.expiresAt && new Date() > new Date(rec.expiresAt); }

function fmtDate(iso) {
    if (!iso) return s("d", "nunca");
    const d = new Date(iso);
    return d.toLocaleDateString("pt-BR") + " " + d.toLocaleTimeString("pt-BR", { hour: "2-digit", minute: "2-digit" });
}

function fmtTimeLeft(rec) {
    if (!rec.expiresAt) return s("G", "vitalicia");
    const ms = new Date(rec.expiresAt) - new Date();
    if (ms <= 0) return s("R", "expirada");
    const d = Math.floor(ms / 86400000);
    const h = Math.floor((ms % 86400000) / 3600000);
    const m = Math.floor((ms % 3600000)  / 60000);
    if (d > 0) return s("C", d + "d " + h + "h restantes");
    if (h > 0) return s("Y", h + "h " + m + "m restantes");
    return s("R", m + "m restantes");
}

function fmtStatus(rec) {
    if (rec.revoked)    return s("R", "REVOGADA");
    if (isExpired(rec)) return s("Y", "EXPIRADA");
    return s("G", "ATIVA   ");
}

function printKey(rec, i, pad) {
    const tc  = TYPE_COL[rec.type] || "d";
    const tl  = TYPE_LBL[rec.type] || rec.type;
    const num = s("d", String(i + 1).padStart(pad || 4) + ".");
    const hwl = rec.hwid
        ? s("G", "\u2713 " + rec.hwid.substring(0, 18) + "...")
        : s("d", "sem hwid");

    console.log("  " + num + "  " + s("b", s("C", rec.key)) +
        "  " + s(tc, tl) + "  " + fmtStatus(rec) + "  " + fmtTimeLeft(rec));
    console.log("       " + s("d", "hwid: ") + hwl +
        (rec.device   ? s("d", "  dev: ")  + s("g", rec.device)             : "") +
        (rec.lastSeen ? s("d", "  seen: ") + s("g", fmtDate(rec.lastSeen))  : ""));
    console.log();
}

// ── BANNER ───────────────────────────────────────────────────────
function banner() {
    console.log();
    console.log(s("b",
        "  \u2554\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2557\n" +
        "  \u2551  Six Painel v4  |  KEY GENERATOR  CLI       \u2551\n" +
        "  \u2551  token admin  :  SIXSEVEN_ADMIN              \u2551\n" +
        "  \u255a\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u255d"
    ));
    console.log();
}

// ── MAIN ─────────────────────────────────────────────────────────
function main() {
    const args = process.argv.slice(2);
    banner();

    // ── sem args ─────────────────────────────────────────────
    if (args.length === 0) {
        const [rec] = generateKeys(1, "forever");
        console.log("  " + s("b", s("G", "Key gerada  (forever):")));
        console.log("  " + s("b", s("C", rec.key)));
        console.log();
        console.log(s("d", "  Tipos disponiveis:"));
        console.log(s("d", "    node keygen.js 10 daily   → 10 keys de 1 dia"));
        console.log(s("d", "    node keygen.js 10 weekly  → 10 keys de 7 dias"));
        console.log(s("d", "    node keygen.js 10 monthly → 10 keys de 30 dias"));
        console.log(s("d", "    node keygen.js 10 forever → 10 keys vitalícias"));
        console.log();
        return;
    }

    // ── --help ───────────────────────────────────────────────
    if (args[0] === "--help" || args[0] === "-h") {
        const ex = (c, d) => console.log("  " + s("C", c.padEnd(40)) + s("d", d));
        console.log(s("Y", s("b", "  Geracao:")));
        ex("(sem args)",               "1 key forever");
        ex("10 daily",                 "10 keys que expiram em 1 dia");
        ex("10 weekly",                "10 keys que expiram em 7 dias");
        ex("10 monthly",               "10 keys que expiram em 30 dias");
        ex("10 forever",               "10 keys vitalícias (nunca expiram)");
        console.log();
        console.log(s("Y", s("b", "  Gerenciamento:")));
        ex("--list",                   "lista todas as keys");
        ex("--list active",            "lista apenas ativas");
        ex("--list expired",           "lista apenas expiradas");
        ex("--list revoked",           "lista apenas revogadas");
        ex("--stats",                  "estatisticas gerais");
        ex("--revoke SIXSEVEN-XXX",       "revoga uma key");
        ex("--reset-hwid SIXSEVEN-XXX",   "desvincula HWID da key");
        ex("--clear",                  "apaga TUDO (cuidado!)");
        console.log();
        return;
    }

    // ── --list [filter] ──────────────────────────────────────
    if (args[0] === "--list") {
        const filter = args[1] || "all";
        const db     = dbLoad();
        const now    = new Date();
        let   list   = db;
        if (filter === "active")  list = db.filter(r => !r.revoked && (!r.expiresAt || new Date(r.expiresAt) > now));
        if (filter === "expired") list = db.filter(r => !r.revoked && r.expiresAt && new Date(r.expiresAt) <= now);
        if (filter === "revoked") list = db.filter(r => r.revoked);

        if (!list.length) {
            console.log(s("Y", "  Nenhuma key encontrada [" + filter + "]\n")); return;
        }
        const pad = String(list.length).length;
        console.log(s("b", "  Keys [" + filter.toUpperCase() + "]  (" + list.length + " total)\n"));
        list.forEach((r, i) => printKey(r, i, pad));
        return;
    }

    // ── --stats ──────────────────────────────────────────────
    if (args[0] === "--stats") {
        const db  = dbLoad();
        const now = new Date();
        const act = db.filter(r => !r.revoked && (!r.expiresAt || new Date(r.expiresAt) > now)).length;
        const exp = db.filter(r => !r.revoked && r.expiresAt && new Date(r.expiresAt) <= now).length;
        const rev = db.filter(r => r.revoked).length;
        const hwi = db.filter(r => r.hwid).length;
        console.log(s("b", "  Estatisticas:\n"));
        console.log("  Total      : " + s("b",  String(db.length)));
        console.log("  Ativas     : " + s("G",  String(act)));
        console.log("  Expiradas  : " + s("Y",  String(exp)));
        console.log("  Revogadas  : " + s("R",  String(rev)));
        console.log("  Com HWID   : " + s("C",  String(hwi)));
        console.log();
        console.log("  Por tipo:");
        ["daily","weekly","monthly","forever"].forEach(t => {
            const cnt = db.filter(r => r.type === t).length;
            console.log("    " + s(TYPE_COL[t] || "d", (TYPE_LBL[t] || t)) + "  " + s("b", String(cnt)));
        });
        console.log();
        return;
    }

    // ── --revoke KEY ─────────────────────────────────────────
    if (args[0] === "--revoke") {
        const key = args[1] || "";
        if (!key) { console.log(s("R", "  Erro: informe a key.\n")); return; }
        const db  = dbLoad();
        const rec = dbFind(db, key);
        if (!rec) { console.log(s("Y", "  Key nao encontrada.\n")); return; }
        rec.revoked = true;
        dbSave(db);
        console.log("  " + s("G", "\u2713") + "  Revogada: " + s("R", rec.key) + "\n");
        return;
    }

    // ── --reset-hwid KEY ─────────────────────────────────────
    if (args[0] === "--reset-hwid") {
        const key = args[1] || "";
        if (!key) { console.log(s("R", "  Erro: informe a key.\n")); return; }
        const db  = dbLoad();
        const rec = dbFind(db, key);
        if (!rec || !rec.hwid) { console.log(s("Y", "  Key sem HWID ou nao encontrada.\n")); return; }
        rec.hwid = null; rec.device = null; rec.hwidBoundAt = null;
        dbSave(db);
        console.log("  " + s("G", "\u2713") + "  HWID resetado: " + s("C", rec.key));
        console.log("  " + s("d", "O proximo dispositivo que validar sera registrado.\n"));
        return;
    }

    // ── --clear ──────────────────────────────────────────────
    if (args[0] === "--clear") {
        const count = dbLoad().length;
        dbSave([]);
        console.log(s("R", s("b", "  \u2713  " + count + " keys removidas.\n")));
        return;
    }

    // ── geracao: node keygen.js [count] [type] ────────────────
    let count = 1;
    let type  = "forever";
    for (const a of args) {
        const n = parseInt(a, 10);
        if (!isNaN(n) && n > 0) { count = n; continue; }
        if (DURATION_MS.hasOwnProperty(a)) { type = a; continue; }
    }
    if (count > 500) { console.log(s("R", "  Limite: 500 keys por vez.\n")); return; }

    const keys = generateKeys(count, type);
    const tc   = TYPE_COL[type] || "d";
    const tl   = TYPE_LBL[type] || type;

    console.log("  Geradas  : " + s("b",  String(keys.length)));
    console.log("  Tipo     : " + s(tc, tl));
    console.log("  Expira   : " + (keys[0]?.expiresAt ? s("Y", fmtDate(keys[0].expiresAt)) : s("G", "nunca")));
    console.log();

    const pad = String(keys.length).length;
    keys.forEach((r, i) =>
        console.log("  " + s("d", String(i+1).padStart(pad)+".") + "  " + s("b", s("C", r.key)))
    );
    console.log();
    console.log("  " + s("G", "\u2713") + "  Salvas em: " + s("d", KEYS_FILE));
    console.log();
}

main();
