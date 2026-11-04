# Mini SOC Lab - Terminal (phase 1): a real Linux shell in the browser, for practice on your own computer.
#
# ttyd serves bash as a web page; the dashboard's Terminal tab shows it. The lab's logs are mounted
# read-only into /home/analyst/logs when the container starts (see soc_lab/terminal.py), so they are
# always the current files and cannot be changed from inside.
#
# Built and started by the dashboard. By hand:
#   docker build -t mini-soc-lab-terminal terminal/
#   python -m soc_lab.cli terminal start

# ttyd is not packaged in Debian stable, so the official static binary is downloaded in a separate stage,
# pinned to a version and checked against the SHA-256 published with that release.
FROM debian:trixie-slim AS ttyd
ARG TTYD_VERSION=1.7.7
ARG TTYD_SHA256_X86_64=8a217c968aba172e0dbf3f34447218dc015bc4d5e59bf51db2f2cd12b7be4f55
ARG TTYD_SHA256_AARCH64=b38acadd89d1d396a0f5649aa52c539edbad07f4bc7348b27b4f4b7219dd4165
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl \
 && arch="$(uname -m)" \
 && case "$arch" in \
      x86_64) sum="$TTYD_SHA256_X86_64" ;; \
      aarch64) sum="$TTYD_SHA256_AARCH64" ;; \
      *) echo "unsupported architecture: $arch" >&2; exit 1 ;; \
    esac \
 && curl -fsSL -o /ttyd "https://github.com/tsl0922/ttyd/releases/download/${TTYD_VERSION}/ttyd.${arch}" \
 && echo "$sum  /ttyd" | sha256sum -c - \
 && chmod 755 /ttyd

FROM debian:trixie-slim

# Tools an analyst uses on logs. No compilers, no network tools: this box is for reading data.
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      bash bash-completion coreutils grep gawk sed less jq file tree procps nano vim-tiny \
 && rm -rf /var/lib/apt/lists/*
COPY --from=ttyd /ttyd /usr/local/bin/ttyd

# An ordinary user, without sudo: nothing in the challenges needs root. ~/logs belongs to root, so the
# analyst can read it but not add, rename or delete files there (the files themselves are mounted read-only).
RUN useradd --create-home --shell /bin/bash analyst \
 && mkdir -m 755 /home/analyst/logs

COPY --chown=analyst:analyst welcome.sh /home/analyst/.welcome.sh
RUN echo '. ~/.welcome.sh' >> /home/analyst/.bashrc

USER analyst
WORKDIR /home/analyst
ENV LANG=C.UTF-8 TERM=xterm-256color

EXPOSE 7681
# --writable lets you type (ttyd is read-only by default); the port is published on 127.0.0.1 only.
CMD ["ttyd", "--writable", "--port", "7681", \
     "--client-option", "fontSize=15", \
     "--client-option", "titleFixed=Mini SOC Lab - Terminal", \
     "bash", "--login"]
