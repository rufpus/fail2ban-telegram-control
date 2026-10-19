FROM ubuntu:24.04
ENV DEBIAN_FRONTEND=noninteractive
RUN printf '#!/bin/sh\nexit 101\n' > /usr/sbin/policy-rc.d \
    && chmod +x /usr/sbin/policy-rc.d \
    && apt-get update \
    && apt-get install -y --no-install-recommends python3 fail2ban nftables iproute2 openssh-server tzdata systemd \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /src
CMD ["bash", ".ci/start.sh"]
