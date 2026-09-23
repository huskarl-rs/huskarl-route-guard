FROM node:24.21.0-bookworm-slim@sha256:0e0ff40c39bc087845bfb27465a0df4ea419520094bc35842ff83dd8cbe6f9b6
WORKDIR /fixture
RUN corepack enable
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml ./
RUN pnpm install --frozen-lockfile
COPY svelte.config.js vite.config.js ./
COPY src ./src
RUN pnpm run build
ENV PORT=8080 HOST=0.0.0.0 ORIGIN=http://localhost
USER node
CMD ["node", "build"]
