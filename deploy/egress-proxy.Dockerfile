FROM node:24-bookworm-slim@sha256:3638d9a6fe4030bd716be989438248074489337ba3275657f93595428be4fc03 AS build
WORKDIR /opt/breach
COPY package.json package-lock.json tsconfig.json tsconfig.base.json ./
COPY packages ./packages
RUN npm ci --ignore-scripts --no-audit --no-fund && npm run build --workspace @breach/security

FROM node:24-bookworm-slim@sha256:3638d9a6fe4030bd716be989438248074489337ba3275657f93595428be4fc03
ENV NODE_ENV=production
WORKDIR /opt/breach
RUN groupadd --system --gid 10001 breach && useradd --system --uid 10001 --gid breach --home-dir /nonexistent --shell /usr/sbin/nologin breach
COPY --from=build --chown=breach:breach /opt/breach/packages/security/dist/proxy.js ./proxy.js
USER breach
EXPOSE 3128
ENTRYPOINT ["node", "proxy.js"]
