# syntax=docker/dockerfile:1

# --- Stage 1: build the TypeScript CLI ---------------------------------------
FROM node:22-slim AS build
WORKDIR /app
COPY package.json package-lock.json tsconfig.json ./
RUN npm ci
COPY src ./src
RUN npm run build && npm prune --omit=dev

# --- Stage 2: runtime with the scanners bundled ------------------------------
FROM node:22-slim

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

WORKDIR /app
COPY --from=build /app/node_modules ./node_modules
COPY --from=build /app/dist ./dist
COPY package.json ./

# The CLI is the entrypoint; args after the image name are passed straight to it.
# Scan a mounted repo:  docker run --rm -v "$PWD:/scan" secsuite-cli scan /scan
ENTRYPOINT ["node", "/app/dist/src/index.js"]
CMD ["--help"]
