# Sandbox for `bouncer detonate`. Runs with --network none; nothing in here
# can reach the internet.
FROM node:22-bookworm-slim

RUN apt-get update \
 && apt-get install -y --no-install-recommends strace openssl ca-certificates curl wget \
      python3 python3-pip python3-setuptools python3-wheel python3-requests python3-urllib3 \
 && rm -rf /var/lib/apt/lists/*

# A throwaway CA that only exists in this image. The fake internet signs a
# certificate for whatever host the package dials, so HTTPS traffic can be read.
RUN mkdir -p /etc/bouncer \
 && openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 3650 \
      -subj "/CN=bouncer sandbox CA" -keyout /etc/bouncer/ca.key -out /etc/bouncer/ca.crt \
 && chmod 600 /etc/bouncer/ca.key \
 && cp /etc/bouncer/ca.crt /usr/local/share/ca-certificates/bouncer-sandbox.crt \
 && update-ca-certificates

RUN useradd -m -s /bin/bash victim
WORKDIR /work
