#!/bin/bash
# Nightly backup. ORDER MATTERS: the database is dumped FIRST, then objects are mirrored. Objects are uploaded before their DB rows are
# confirmed, so objects taken later are a superset of what the dump references (orphans are harmless; missing files would not be).
set -euo pipefail
TS=$(date +%Y%m%d-%H%M%S); DIR=/backups; mkdir -p $DIR/db $DIR/objects
echo "[$TS] database dump"
pg_dump -Fc --no-owner "$PGDATABASE" | openssl enc -aes-256-cbc -pbkdf2 -salt -pass env:BACKUP_PASSPHRASE -out "$DIR/db/gatepass-$TS.dump.enc"
psql -Atc "SELECT row_hash FROM audit_logs ORDER BY id DESC LIMIT 1" 2>/dev/null | head -1 > "$DIR/db/gatepass-$TS.audit-head.txt" || true   # anchor of the audit hash chain
echo "[$TS] object mirror (local)"
mc alias set src "$MINIO_ENDPOINT" "$MINIO_ROOT_USER" "$MINIO_ROOT_PASSWORD" >/dev/null
mc mirror --overwrite --quiet "src/$S3_BUCKET" "$DIR/objects/$S3_BUCKET"
if [ -n "${OFFSITE_S3_ENDPOINT:-}" ]; then
  echo "[$TS] offsite copy"
  mc alias set offsite "$OFFSITE_S3_ENDPOINT" "$OFFSITE_S3_ACCESS_KEY" "$OFFSITE_S3_SECRET_KEY" >/dev/null
  mc mirror --overwrite --quiet "$DIR/objects/$S3_BUCKET" "offsite/$OFFSITE_S3_BUCKET/objects"
  mc cp --quiet "$DIR/db/gatepass-$TS.dump.enc" "$DIR/db/gatepass-$TS.audit-head.txt" "offsite/$OFFSITE_S3_BUCKET/db/"
else
  echo "WARNING: OFFSITE_S3_ENDPOINT is not set - backups exist only on this server"
fi
# retention: 7 daily, 4 weekly (Sunday), 12 monthly (1st) - everything else pruned
find $DIR/db -name 'gatepass-*.dump.enc' -mtime +7 | while read f; do d=$(basename "$f" | sed -E 's/gatepass-([0-9]{8}).*/\1/'); dow=$(date -d "$d" +%u); dom=$(date -d "$d" +%d)
  if [ "$dom" = "01" ] && [ "$(( ($(date +%s) - $(date -d "$d" +%s)) / 86400 ))" -lt 365 ]; then continue; fi
  if [ "$dow" = "7" ] && [ "$(( ($(date +%s) - $(date -d "$d" +%s)) / 86400 ))" -lt 31 ]; then continue; fi
  rm -f "$f" "${f%.dump.enc}.audit-head.txt"; done
echo "$TS ok" > $DIR/last_backup_status
echo "[$TS] backup complete"
