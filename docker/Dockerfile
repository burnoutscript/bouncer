# Sandbox for `bouncer detonate`. Runs with --network none; nothing in here
# can reach the internet.
FROM node:22-bookworm-slim

RUN apt-get update \
 && apt-get install -y --no-install-recommends strace python3 python3-pip python3-setuptools python3-wheel curl wget ca-certificates \
 && rm -rf /var/lib/apt/lists/*

RUN useradd -m -s /bin/bash victim
WORKDIR /work
