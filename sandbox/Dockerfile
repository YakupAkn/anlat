FROM debian:12-slim
RUN apt-get update && apt-get install -y --no-install-recommends strace ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd -m -d /home/user -s /bin/bash user
COPY runner.sh /runner.sh
RUN chmod +x /runner.sh
CMD ["/runner.sh"]
