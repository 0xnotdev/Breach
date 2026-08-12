FROM node:24-bookworm-slim@sha256:3638d9a6fe4030bd716be989438248074489337ba3275657f93595428be4fc03 AS build
WORKDIR /opt/breach
COPY package.json package-lock.json tsconfig.json tsconfig.base.json ./
COPY packages ./packages
COPY apps ./apps
RUN npm ci --ignore-scripts --no-audit --no-fund && npm run build --workspace @breach/web

FROM node:24-bookworm-slim@sha256:3638d9a6fe4030bd716be989438248074489337ba3275657f93595428be4fc03
ENV NODE_ENV=production
WORKDIR /opt/breach
RUN groupadd --system --gid 10001 breach && useradd --system --uid 10001 --gid breach --home-dir /nonexistent --shell /usr/sbin/nologin breach
COPY --from=build --chown=breach:breach /opt/breach/node_modules ./node_modules
COPY --from=build --chown=breach:breach /opt/breach/apps/web ./apps/web
USER breach
EXPOSE 3000
WORKDIR /opt/breach/apps/web
ENTRYPOINT ["node", "node_modules/vinext/dist/cli.js", "start", "--port", "3000", "--hostname", "0.0.0.0"]
