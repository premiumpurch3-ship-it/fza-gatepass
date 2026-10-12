FROM alpine:3.20
RUN apk add --no-cache postgresql16-client minio-client bash openssl tzdata dcron curl
COPY backup.sh restore.sh verify-restore.sh crontab /opt/
RUN chmod +x /opt/*.sh && crontab /opt/crontab
ENV TZ=Asia/Karachi
CMD ["crond", "-f", "-l", "8"]
