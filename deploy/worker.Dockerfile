FROM node:24-bookworm-slim AS build
WORKDIR /opt/breach
COPY package.json package-lock.json tsconfig.json tsconfig.base.json vitest.config.ts ./
COPY packages ./packages
COPY apps/worker ./apps/worker
RUN npm ci --ignore-scripts --no-audit --no-fund && npm run build

FROM node:24-bookworm-slim AS runtime
ENV NODE_ENV=production
WORKDIR /opt/breach
RUN groupadd --system --gid 10001 breach && useradd --system --uid 10001 --gid breach --home-dir /nonexistent --shell /usr/sbin/nologin breach
COPY --from=build --chown=breach:breach /opt/breach/node_modules ./node_modules
COPY --from=build --chown=breach:breach /opt/breach/packages ./packages
COPY --from=build --chown=breach:breach /opt/breach/apps/worker/dist ./apps/worker/dist
USER breach
ENTRYPOINT ["node", "apps/worker/dist/index.js"]
