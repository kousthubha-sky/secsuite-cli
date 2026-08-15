# syntax=docker/dockerfile:1

# --- Stage 1: build the Go CLI -----------------------------------------------
FROM golang:1.26-bookworm AS build
WORKDIR /app

# Dependencies first so a source-only change reuses this layer.
COPY go.mod go.sum ./
RUN go mod download

COPY cmd ./cmd
COPY internal ./internal

# Overridden at build time to match the release tag:
#   docker build --build-arg VERSION=0.3.0 .
ARG VERSION=dev
RUN CGO_ENABLED=0 go build -ldflags="-s -w -X main.version=${VERSION}" -o /out/secsuite ./cmd/secsuite

# --- Stage 2: runtime with the scanners bundled ------------------------------
# The binary is static, so this only needs to carry the scanners themselves.
FROM debian:bookworm-slim

# Which gitleaks release to bundle (bump as needed).
ARG GITLEAKS_VERSION=8.18.4

# Install the static scanners so `secsuite scan` works out of the box:
#   - semgrep (SAST) via pip
#   - trivy (SCA / IaC / secrets) via its official install script
#   - gitleaks (secrets, incl. git history) from its GitHub release
# git is needed for gitleaks' history scan.
RUN apt-get update \
 && apt-get install -y --no-install-recommends python3 python3-pip curl ca-certificates git tar \
 && pip3 install --no-cache-dir --break-system-packages semgrep \
 && curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin \
 && curl -sfL "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz" \
    | tar -xz -C /usr/local/bin gitleaks \
 && apt-get purge -y curl \
 && apt-get autoremove -y \
 && rm -rf /var/lib/apt/lists/*

COPY --from=build /out/secsuite /usr/local/bin/secsuite

# Don't run as root. The scanner user needs a writable home for the tools'
# caches (trivy's vuln DB, semgrep's rule cache).
RUN useradd --create-home --shell /usr/sbin/nologin scanner
USER scanner
ENV HOME=/home/scanner
WORKDIR /home/scanner

# The CLI is the entrypoint; args after the image name are passed straight to it.
# Scan a mounted repo:  docker run --rm -v "$PWD:/scan" secsuite-cli scan /scan
ENTRYPOINT ["/usr/local/bin/secsuite"]
CMD ["--help"]
