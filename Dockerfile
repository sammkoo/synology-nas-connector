FROM node:22-bookworm-slim AS build
RUN apt-get update && apt-get install -y --no-install-recommends openssl && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY package*.json ./
COPY packages/core/package.json packages/core/package.json
COPY packages/auth/package.json packages/auth/package.json
COPY packages/management/package.json packages/management/package.json
COPY packages/gateway/package.json packages/gateway/package.json
COPY packages/relay/package.json packages/relay/package.json
COPY apps/server/package.json apps/server/package.json
COPY apps/gateway/package.json apps/gateway/package.json
COPY apps/dsm-ui/package.json apps/dsm-ui/package.json
COPY apps/dsm-bridge/package.json apps/dsm-bridge/package.json
RUN npm ci
COPY . .
RUN npm run check

FROM node:22-bookworm-slim AS runtime
WORKDIR /app
COPY --from=build --chown=node:node /app/dist ./dist
USER node
ENV NAS_CONNECTOR_CONFIG=/config/config.json NAS_CONNECTOR_UI_DIR=/app/dist/ui
EXPOSE 8787
HEALTHCHECK --interval=30s --timeout=3s CMD node -e "fetch('http://127.0.0.1:8787/healthz').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"
CMD ["node", "dist/server.cjs"]

FROM runtime AS gateway
USER root
# Empty named volumes inherit these private directories and the service owner.
RUN mkdir -p /config /state && chown node:node /config /state && chmod 700 /config /state
USER node
ENV NAS_GATEWAY_CONFIG=/config/config.json WS_NO_BUFFER_UTIL=1 WS_NO_UTF_8_VALIDATE=1
EXPOSE 8788
HEALTHCHECK --interval=30s --timeout=4s CMD node dist/gateway.cjs --healthcheck
CMD ["node", "dist/gateway.cjs"]

# Preserve the existing default NAS image; gateway is selected with --target.
FROM runtime AS connector
