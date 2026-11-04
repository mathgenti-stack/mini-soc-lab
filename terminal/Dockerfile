# Mini SOC Lab - Terminal: a real Linux shell (phase 1) and PowerShell 7 (phase 2) in the browser,
# for practice on your own computer.
#
# ttyd serves the shell as a web page; the dashboard's Terminal tab shows it. The lab's logs are mounted
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

# PowerShell 7 (phase 2): the official Linux build, pinned to a version and checked against the SHA-256
# published with that release (hashes.sha256). 7.6 is the current long-term support (LTS) line.
FROM debian:trixie-slim AS pwsh
ARG PWSH_VERSION=7.6.9
ARG PWSH_SHA256_X64=1da6d6d6035d651f20e70ddee7c4c15ac6ab8b9fb40ee92240d91263f28a884b
ARG PWSH_SHA256_ARM64=02eb9991af447c7e7fe881acde195961afd397c40b8eb1c2b3856b84ec2d85f2
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl \
 && case "$(uname -m)" in \
      x86_64) arch=x64; sum="$PWSH_SHA256_X64" ;; \
      aarch64) arch=arm64; sum="$PWSH_SHA256_ARM64" ;; \
      *) echo "unsupported architecture: $(uname -m)" >&2; exit 1 ;; \
    esac \
 && curl -fsSL -o /pwsh.tar.gz \
      "https://github.com/PowerShell/PowerShell/releases/download/v${PWSH_VERSION}/powershell-${PWSH_VERSION}-linux-${arch}.tar.gz" \
 && echo "$sum  /pwsh.tar.gz" | sha256sum -c - \
 && mkdir -p /opt/microsoft/powershell/7 \
 && tar -xzf /pwsh.tar.gz -C /opt/microsoft/powershell/7 \
 && chmod 755 /opt/microsoft/powershell/7/pwsh

FROM debian:trixie-slim

# Tools an analyst uses on logs. No compilers, no network tools: this box is for reading data.
# libicu and libssl are what PowerShell (.NET) needs; python3 runs the lab's .evtx reader for Get-WinEvent.
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      bash bash-completion coreutils grep gawk sed less jq file tree procps nano vim-tiny \
      ca-certificates libicu76 libssl3t64 python3 \
 && rm -rf /var/lib/apt/lists/*
COPY --from=ttyd /ttyd /usr/local/bin/ttyd
COPY --from=pwsh /opt/microsoft/powershell/7 /opt/microsoft/powershell/7
RUN ln -s /opt/microsoft/powershell/7/pwsh /usr/local/bin/pwsh
ENV POWERSHELL_TELEMETRY_OPTOUT=1 POWERSHELL_UPDATECHECK=Off DOTNET_CLI_TELEMETRY_OPTOUT=1

# Get-WinEvent for Linux (module SocLab, loaded on first use) and the .evtx reader it calls. The reader's
# code, soc_lab/evtx.py, is mounted read-only at /opt/soc-lab/lib when the container starts.
COPY SocLab /usr/local/share/powershell/Modules/SocLab
COPY evtx_dump.py /opt/soc-lab/evtx_dump.py
COPY --chmod=755 lab-shell /usr/local/bin/lab-shell

# An ordinary user, without sudo: nothing in the challenges needs root. ~/logs belongs to root, so the
# analyst can read it but not add, rename or delete files there (the files themselves are mounted read-only).
RUN useradd --create-home --shell /bin/bash analyst \
 && mkdir -m 755 /home/analyst/logs

COPY --chown=analyst:analyst welcome.sh /home/analyst/.welcome.sh
RUN echo '. ~/.welcome.sh' >> /home/analyst/.bashrc
COPY --chown=analyst:analyst profile.ps1 /home/analyst/.config/powershell/Microsoft.PowerShell_profile.ps1

USER analyst
WORKDIR /home/analyst
ENV LANG=C.UTF-8 TERM=xterm-256color

EXPOSE 7681
# --writable lets you type (ttyd is read-only by default); the port is published on 127.0.0.1 only.
# --url-arg passes ?arg=... from the page address to lab-shell, which accepts only bash or powershell.
CMD ["ttyd", "--writable", "--url-arg", "--port", "7681", \
     "--client-option", "fontSize=15", \
     "--client-option", "titleFixed=Mini SOC Lab - Terminal", \
     "lab-shell"]
