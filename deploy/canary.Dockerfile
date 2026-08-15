FROM node:24-bookworm-slim@sha256:3638d9a6fe4030bd716be989438248074489337ba3275657f93595428be4fc03 AS build
WORKDIR /opt/breach
COPY package.json package-lock.json tsconfig.json tsconfig.base.json vitest.config.ts ./
COPY packages ./packages
COPY apps ./apps
COPY fixtures/canary-repository/credential.txt ./fixtures/canary-repository/credential.txt
RUN npm ci --ignore-scripts --no-audit --no-fund && npm run build --workspace @breach/worker

FROM node:24-bookworm-slim@sha256:3638d9a6fe4030bd716be989438248074489337ba3275657f93595428be4fc03
ENV NODE_ENV=production
WORKDIR /opt/breach
RUN groupadd --system --gid 10001 breach && useradd --system --uid 10001 --gid breach --home-dir /nonexistent --shell /usr/sbin/nologin breach
COPY --from=build --chown=breach:breach /opt/breach/node_modules ./node_modules
COPY --from=build --chown=breach:breach /opt/breach/packages ./packages
COPY --from=build --chown=breach:breach /opt/breach/apps/worker/dist ./apps/worker/dist
COPY --from=build --chown=breach:breach /opt/breach/fixtures/canary-repository/credential.txt ./fixtures/canary-repository/credential.txt
USER breach
ENTRYPOINT ["node", "apps/worker/dist/canary.js"]
