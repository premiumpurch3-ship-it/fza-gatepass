#!/bin/bash
# Restore a database backup into a target database. Usage: restore.sh <backup.dump.enc> [target_db]
# For disaster recovery run with the application stopped, then restore objects with: mc mirror /backups/objects/<bucket> src/<bucket>
set -euo pipefail
FILE=${1:?usage: restore.sh <backup.dump.enc> [target_db]}; TARGET=${2:-$PGDATABASE}
openssl enc -d -aes-256-cbc -pbkdf2 -pass env:BACKUP_PASSPHRASE -in "$FILE" | pg_restore --clean --if-exists --no-owner -d "$TARGET"
echo "restored $FILE into $TARGET"
