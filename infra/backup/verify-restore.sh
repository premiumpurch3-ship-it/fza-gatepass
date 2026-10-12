#!/bin/bash
# Monthly restore drill: restore the newest backup into a scratch database, then check row counts and the audit hash chain.
set -euo pipefail
export PGUSER=${DRILL_PGUSER:-$PGUSER} PGPASSWORD=${DRILL_PGPASSWORD:-$PGPASSWORD}
LATEST=$(ls -1t /backups/db/gatepass-*.dump.enc | head -1); SCRATCH=restore_check_$(date +%s)
psql -d postgres -Atc "CREATE DATABASE $SCRATCH" 2>/dev/null || { echo "the drill user cannot create databases (set DRILL_PGUSER/DRILL_PGPASSWORD to an admin role)"; exit 2; }
/opt/restore.sh "$LATEST" "$SCRATCH"
echo "users: $(psql -d $SCRATCH -Atc 'select count(*) from users')  gate_passes: $(psql -d $SCRATCH -Atc 'select count(*) from gate_passes')"
echo "audit chain: $(psql -d $SCRATCH -Atc "select case when first_bad is null then 'OK ('||rows_checked||' rows)' else 'BROKEN at '||first_bad end from audit_verify_chain(0)")"
psql -d postgres -Atc "DROP DATABASE $SCRATCH"
echo "restore drill finished for $LATEST"
