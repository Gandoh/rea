# Production Multi-Stage Dockerfile for REA Cloud Studio
# Build from repository root:
#   docker build -f studio/Dockerfile -t rea-cloud-studio:latest .
# Run (mount a persistent volume at /data and set PUBLIC_BASE_URL in production):
#   docker run --rm -p 3080:3080 \
#     -v rea_studio_data:/data \
#     -e PUBLIC_BASE_URL=https://studio.example.com \
#     -e REA_BOOTSTRAP_API_KEY=rea_sk_live_replace_with_20plus_char_secret \
#     rea-cloud-studio:latest

FROM node:24.22.1-bookworm-slim AS builder
WORKDIR /app

COPY package.json package-lock.json .npmrc .nvmrc turbo.json tsconfig*.json ./
COPY .agents/skills/reverse-engineer-anything ./.agents/skills/reverse-engineer-anything
COPY scripts ./scripts
COPY src ./src
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
COPY bridge ./bridge
COPY website/public/examples/notes-electron ./website/public/examples/notes-electron
COPY studio ./studio
RUN HUSKY=0 npm ci --prefix studio --omit=dev --ignore-scripts --no-audit --no-fund

ENV NODE_ENV=production
ENV HOST=0.0.0.0
ENV PORT=3080
ENV REA_STUDIO_RUNTIME_DIR=/tmp/rea-studio-runtime
ENV REA_STUDIO_DATA_DIR=/data

RUN mkdir -p -m 0700 /tmp/rea-studio-runtime /data && chown -R node:node /app /tmp/rea-studio-runtime /data
VOLUME ["/data"]
USER node

EXPOSE 3080

HEALTHCHECK --interval=20s --timeout=5s --start-period=15s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:' + (process.env.PORT || 3080) + '/api/health').then(r => process.exit(r.ok ? 0 : 1)).catch(() => process.exit(1))"

CMD ["node", "studio/server/index.mjs"]
