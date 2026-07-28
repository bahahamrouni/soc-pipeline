import argparse, json
from collections import Counter
import psycopg2
import psycopg2.extras

ap = argparse.ArgumentParser()
ap.add_argument("--pg-host", required=True)
ap.add_argument("--pg-db", required=True)
ap.add_argument("--pg-user", required=True)
ap.add_argument("--pg-password", required=True)
args = ap.parse_args()

conn = psycopg2.connect(host=args.pg_host, port=5432, dbname=args.pg_db,
                         user=args.pg_user, password=args.pg_password)
cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
cur.execute("SELECT id, first_seen, raw_incident FROM incidents ORDER BY first_seen")
rows = cur.fetchall()
print(f"Total incidents in database: {len(rows)}")

rule_counter = Counter()
earliest = {}
latest = {}
for row in rows:
    raw = row["raw_incident"]
    if isinstance(raw, str):
        raw = json.loads(raw)
    rule_id = raw.get("correlation_rule", {}).get("id", "UNKNOWN")
    rule_counter[rule_id] += 1
    ts = row["first_seen"]
    if rule_id not in earliest or ts < earliest[rule_id]:
        earliest[rule_id] = ts
    if rule_id not in latest or ts > latest[rule_id]:
        latest[rule_id] = ts

print("\nCorrelation rule distribution across ALL incidents ever stored:")
for rule_id, count in rule_counter.most_common():
    print(f"  {rule_id}: {count} incidents, first={earliest[rule_id]}, last={latest[rule_id]}")