#!/bin/bash
# First-time TLS bootstrap: starts Nginx with a throw-away self-signed certificate, requests the real Let's Encrypt certificate via
# the HTTP-01 challenge, then reloads Nginx. Run once from infra/ after creating infra/.env and pointing DNS at this server.
set -euo pipefail
cd "$(dirname "$0")"; set -a; . ./.env; set +a
: "${DOMAIN:?}" "${LETSENCRYPT_EMAIL:?}"
echo "### dummy certificate for $DOMAIN"
docker compose run --rm --entrypoint "sh -c 'mkdir -p /etc/letsencrypt/live/$DOMAIN && openssl req -x509 -nodes -newkey rsa:2048 -days 1 -keyout /etc/letsencrypt/live/$DOMAIN/privkey.pem -out /etc/letsencrypt/live/$DOMAIN/fullchain.pem -subj /CN=localhost'" certbot
docker compose up -d nginx
echo "### requesting Let's Encrypt certificate"
docker compose run --rm --entrypoint "sh -c 'rm -rf /etc/letsencrypt/live/$DOMAIN /etc/letsencrypt/archive/$DOMAIN /etc/letsencrypt/renewal/$DOMAIN.conf; certbot certonly --webroot -w /var/www/certbot -d $DOMAIN -d files.$DOMAIN --email $LETSENCRYPT_EMAIL --agree-tos --no-eff-email --force-renewal'" certbot
docker compose exec nginx nginx -s reload
echo "### done: https://$DOMAIN"
