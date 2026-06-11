#!/usr/bin/env python3
"""
SOC Dashboard - FastAPI Backend
Serves incident data from PostgreSQL + pipeline health metrics
"""

import os
import json
import logging
from datetime import datetime, timezone, timedelta
from typing import Optional, List
from contextlib import asynccontextmanager

import psycopg2
import psycopg2.extras
from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ── DB config ────────────────────────────────────────────
DB_CONFIG = {
    "host":     os.environ.get("POSTGRES_HOST", "postgres"),
    "port":     int(os.environ.get("POSTGRES_PORT", 5432)),
    "dbname":   os.environ.get("POSTGRES_DB", "socdb"),
    "user":     os.environ.get("POSTGRES_USER", "socadmin"),
    "password": os.environ.get("POSTGRES_PASSWORD", "S0cAdmin!"),
}

SEVERITY_LABELS = {0: "info", 1: "medium", 2: "high", 3: "critical"}
SEVERITY_FR     = {0: "Info", 1: "Moyen", 2: "Élevé", 3: "Critique"}

# ── DB helpers ───────────────────────────────────────────
def get_conn():
    return psycopg2.connect(**DB_CONFIG)

def query(sql, params=None):
    with get_conn() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(sql, params)
            return cur.fetchall()

def query_one(sql, params=None):
    with get_conn() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(sql, params)
            return cur.fetchone()

# ── App ──────────────────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("SOC Dashboard API starting...")
    yield
    logger.info("SOC Dashboard API stopped")

app = FastAPI(
    title="HACO SOC Dashboard API",
    description="API du Centre des Opérations de Sécurité - HACO S.A.",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Models ───────────────────────────────────────────────
class IncidentUpdate(BaseModel):
    status: Optional[str] = None
    assigned_to: Optional[str] = None
    analyst_notes: Optional[str] = None

# ── Helpers ──────────────────────────────────────────────
def format_incident(row):
    row = dict(row)
    row["severity_label"] = SEVERITY_LABELS.get(row.get("severity"), "unknown")
    row["severity_fr"]    = SEVERITY_FR.get(row.get("severity"), "Inconnu")
    # Convert non-serializable types
    for k, v in row.items():
        if isinstance(v, datetime):
            row[k] = v.isoformat()
    if row.get("source_ips"):
        row["source_ips"] = [str(ip) for ip in row["source_ips"]]
    return row

# ════════════════════════════════════════════════════════
#  HEALTH
# ════════════════════════════════════════════════════════
@app.get("/api/health")
def health():
    try:
        result = query_one("SELECT COUNT(*) as cnt FROM incidents")
        pg_ok = True
        pg_count = result["cnt"]
    except Exception as e:
        pg_ok = False
        pg_count = 0

    return {
        "status": "ok" if pg_ok else "degraded",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "services": {
            "postgresql": {"status": "up" if pg_ok else "down", "incidents": pg_count},
        }
    }

# ════════════════════════════════════════════════════════
#  STATS
# ════════════════════════════════════════════════════════
@app.get("/api/stats/summary")
def stats_summary():
    total       = query_one("SELECT COUNT(*) as cnt FROM incidents")["cnt"]
    open_count  = query_one("SELECT COUNT(*) as cnt FROM incidents WHERE status='open'")["cnt"]
    critical    = query_one("SELECT COUNT(*) as cnt FROM incidents WHERE severity=3")["cnt"]
    high        = query_one("SELECT COUNT(*) as cnt FROM incidents WHERE severity=2")["cnt"]
    medium      = query_one("SELECT COUNT(*) as cnt FROM incidents WHERE severity=1")["cnt"]
    info        = query_one("SELECT COUNT(*) as cnt FROM incidents WHERE severity=0")["cnt"]
    true_pos    = query_one(
        "SELECT COUNT(*) as cnt FROM incidents WHERE raw_incident->'ai_inference'->>'is_true_positive'='true'"
    )["cnt"]

    by_category = query(
        "SELECT category, COUNT(*) as cnt FROM incidents GROUP BY category ORDER BY cnt DESC LIMIT 8"
    )
    by_status = query(
        "SELECT status, COUNT(*) as cnt FROM incidents GROUP BY status"
    )

    return {
        "total":        total,
        "open":         open_count,
        "critical":     critical,
        "high":         high,
        "medium":       medium,
        "info":         info,
        "true_positives": true_pos,
        "by_severity": [
            {"name": "Critique", "value": critical, "color": "#ef4444"},
            {"name": "Élevé",    "value": high,     "color": "#f97316"},
            {"name": "Moyen",    "value": medium,   "color": "#eab308"},
            {"name": "Info",     "value": info,     "color": "#3b82f6"},
        ],
        "by_category": [dict(r) for r in by_category],
        "by_status":   [dict(r) for r in by_status],
    }


@app.get("/api/stats/timeline")
def stats_timeline(period: str = Query("24h", pattern="^(24h|7d|30d)$")):
    if period == "24h":
        interval = "1 hour"
        since    = "now() - interval '24 hours'"
        fmt      = "HH24:MI"
    elif period == "7d":
        interval = "1 day"
        since    = "now() - interval '7 days'"
        fmt      = "DD/MM"
    else:
        interval = "1 day"
        since    = "now() - interval '30 days'"
        fmt      = "DD/MM"

    sql = f"""
        SELECT
            to_char(date_trunc('{interval.split()[1]}', created_at), '{fmt}') as label,
            COUNT(*) as total,
            COUNT(*) FILTER (WHERE severity = 3) as critical,
            COUNT(*) FILTER (WHERE severity = 2) as high,
            COUNT(*) FILTER (WHERE severity = 1) as medium
        FROM incidents
        WHERE created_at >= {since}
        GROUP BY date_trunc('{interval.split()[1]}', created_at)
        ORDER BY date_trunc('{interval.split()[1]}', created_at)
    """
    rows = query(sql)
    return [dict(r) for r in rows]


@app.get("/api/stats/top-hosts")
def stats_top_hosts(limit: int = Query(10, ge=1, le=50)):
    sql = """
        SELECT
            unnest(target_hosts) as host,
            COUNT(*) as incident_count,
            MAX(severity) as max_severity
        FROM incidents
        WHERE target_hosts IS NOT NULL
        GROUP BY host
        ORDER BY incident_count DESC
        LIMIT %s
    """
    rows = query(sql, (limit,))
    return [dict(r) for r in rows]


@app.get("/api/stats/top-rules")
def stats_top_rules(limit: int = Query(10, ge=1, le=50)):
    sql = """
        SELECT
            raw_incident->'correlation_rule'->>'id'   as rule_id,
            raw_incident->'correlation_rule'->>'name' as rule_name,
            COUNT(*) as fired_count,
            AVG(confidence) as avg_confidence
        FROM incidents
        GROUP BY rule_id, rule_name
        ORDER BY fired_count DESC
        LIMIT %s
    """
    rows = query(sql, (limit,))
    result = []
    for r in rows:
        d = dict(r)
        if d.get("avg_confidence"):
            d["avg_confidence"] = round(float(d["avg_confidence"]), 3)
        result.append(d)
    return result


@app.get("/api/stats/confidence-distribution")
def stats_confidence():
    sql = """
        SELECT
            CASE
                WHEN confidence >= 0.9 THEN '90-100%'
                WHEN confidence >= 0.7 THEN '70-90%'
                WHEN confidence >= 0.5 THEN '50-70%'
                ELSE '<50%'
            END as range,
            COUNT(*) as count
        FROM incidents
        WHERE confidence IS NOT NULL
        GROUP BY range
        ORDER BY range DESC
    """
    rows = query(sql)
    return [dict(r) for r in rows]


# ════════════════════════════════════════════════════════
#  INCIDENTS
# ════════════════════════════════════════════════════════
@app.get("/api/incidents")
def list_incidents(
    page:     int = Query(1, ge=1),
    per_page: int = Query(20, ge=1, le=100),
    severity: Optional[int]  = Query(None),
    status:   Optional[str]  = Query(None),
    category: Optional[str]  = Query(None),
    search:   Optional[str]  = Query(None),
    sort:     str  = Query("created_at"),
    order:    str  = Query("desc"),
):
    conditions = []
    params     = []

    if severity is not None:
        conditions.append("severity = %s")
        params.append(severity)
    if status:
        conditions.append("status = %s")
        params.append(status)
    if category:
        conditions.append("category ILIKE %s")
        params.append(f"%{category}%")
    if search:
        conditions.append("""(
            raw_incident::text ILIKE %s
            OR category ILIKE %s
            OR EXISTS (SELECT 1 FROM unnest(target_hosts) h WHERE h ILIKE %s)
        )""")
        params.extend([f"%{search}%", f"%{search}%", f"%{search}%"])

    where = ("WHERE " + " AND ".join(conditions)) if conditions else ""

    allowed_sorts  = {"created_at", "severity", "confidence", "event_count"}
    allowed_orders = {"asc", "desc"}
    sort  = sort  if sort  in allowed_sorts  else "created_at"
    order = order if order in allowed_orders else "desc"

    count_sql = f"SELECT COUNT(*) as cnt FROM incidents {where}"
    total     = query_one(count_sql, params or None)["cnt"]

    offset = (page - 1) * per_page
    data_sql = f"""
        SELECT id, created_at, severity, category, confidence,
               status, event_count, source_ips, target_hosts,
               first_seen, last_seen, assigned_to,
               raw_incident->'correlation_rule'->>'id'   as rule_id,
               raw_incident->'correlation_rule'->>'name' as rule_name,
               raw_incident->'ai_inference'->>'attack_class'     as attack_class,
               raw_incident->'ai_inference'->>'is_true_positive' as is_true_positive
        FROM incidents {where}
        ORDER BY {sort} {order}
        LIMIT %s OFFSET %s
    """
    rows = query(data_sql, (params + [per_page, offset]) if params else [per_page, offset])

    return {
        "total":    total,
        "page":     page,
        "per_page": per_page,
        "pages":    (total + per_page - 1) // per_page,
        "items":    [format_incident(r) for r in rows],
    }


@app.get("/api/incidents/recent")
def recent_incidents(limit: int = Query(10, ge=1, le=50)):
    sql = """
        SELECT id, created_at, severity, category, confidence,
               status, event_count, target_hosts,
               raw_incident->'correlation_rule'->>'id'   as rule_id,
               raw_incident->'correlation_rule'->>'name' as rule_name,
               raw_incident->'ai_inference'->>'attack_class'     as attack_class,
               raw_incident->'ai_inference'->>'is_true_positive' as is_true_positive
        FROM incidents
        ORDER BY created_at DESC
        LIMIT %s
    """
    rows = query(sql, (limit,))
    return [format_incident(r) for r in rows]


@app.get("/api/incidents/{incident_id}")
def get_incident(incident_id: str):
    row = query_one(
        "SELECT * FROM incidents WHERE id = %s", (incident_id,)
    )
    if not row:
        raise HTTPException(status_code=404, detail="Incident non trouvé")
    return format_incident(row)


@app.patch("/api/incidents/{incident_id}")
def update_incident(incident_id: str, update: IncidentUpdate):
    fields, params = [], []
    if update.status is not None:
        fields.append("status = %s")
        params.append(update.status)
    if update.assigned_to is not None:
        fields.append("assigned_to = %s")
        params.append(update.assigned_to)
    if update.analyst_notes is not None:
        fields.append("analyst_notes = %s")
        params.append(update.analyst_notes)

    if not fields:
        raise HTTPException(status_code=400, detail="Aucun champ à mettre à jour")

    fields.append("updated_at = now()")
    params.append(incident_id)

    sql = f"UPDATE incidents SET {', '.join(fields)} WHERE id = %s RETURNING id"
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(sql, params)
            if cur.fetchone() is None:
                raise HTTPException(status_code=404, detail="Incident non trouvé")
        conn.commit()

    return {"message": "Incident mis à jour"}


# ── Serve React frontend ─────────────────────────────────
STATIC_DIR = "/app/static"
if os.path.exists(STATIC_DIR):
    app.mount("/assets", StaticFiles(directory=f"{STATIC_DIR}/assets"), name="assets")

    @app.get("/{full_path:path}")
    def serve_frontend(full_path: str):
        return FileResponse(f"{STATIC_DIR}/index.html")