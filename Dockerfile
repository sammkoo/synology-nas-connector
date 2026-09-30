FROM node:22-bookworm-slim AS build
WORKDIR /app
COPY package*.json ./
COPY packages/core/package.json packages/core/package.json
COPY packages/auth/package.json packages/auth/package.json
COPY packages/management/package.json packages/management/package.json
COPY apps/server/package.json apps/server/package.json
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
