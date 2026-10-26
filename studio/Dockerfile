# Production Multi-Stage Dockerfile for REA Cloud Studio
# Build from repository root:
#   docker build -f studio/Dockerfile -t rea-cloud-studio:latest .
# Run:
#   docker run --rm -p 3080:3080 -e REA_BOOTSTRAP_API_KEY=rea_sk_live_prod rea-cloud-studio:latest

FROM node:24.22.1-bookworm-slim AS builder
WORKDIR /app

COPY package.json package-lock.json .npmrc tsconfig*.json ./
COPY scripts ./scripts
COPY src ./src
COPY skills ./skills
COPY LICENSE DISCLAIMER.md THIRD_PARTY_NOTICES.md README.md ./

RUN HUSKY=0 npm ci && npm run build:cached && npm prune --omit=dev

FROM node:24.22.1-bookworm-slim AS runtime
WORKDIR /app

# Install open static inspection tools used by REA ShipGate & startup sample generator
RUN apt-get update && apt-get install -y --no-install-recommends \
      binutils \
      gcc \
      libc6-dev \
      python3 \
      ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Preserve MIT copyright & third-party notices in commercial redistributions
COPY --from=builder /app/LICENSE /app/DISCLAIMER.md /app/THIRD_PARTY_NOTICES.md ./
COPY --from=builder /app/package.json ./
COPY --from=builder /app/node_modules ./node_modules
COPY --from=builder /app/dist ./dist
COPY website/public/examples/notes-electron ./website/public/examples/notes-electron
COPY studio ./studio

ENV NODE_ENV=production
ENV HOST=0.0.0.0
ENV PORT=3080
ENV REA_STUDIO_RUNTIME_DIR=/tmp/rea-studio-runtime
ENV REA_STUDIO_DATA_DIR=/data

RUN mkdir -p /tmp/rea-studio-runtime /data && chown -R node:node /app /tmp/rea-studio-runtime /data
VOLUME ["/data"]
USER node

EXPOSE 3080

HEALTHCHECK --interval=20s --timeout=5s --start-period=10s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:' + (process.env.PORT || 3080) + '/api/health').then(r => process.exit(r.ok ? 0 : 1)).catch(() => process.exit(1))"

CMD ["node", "studio/server/index.mjs"]
