# syntax=docker/dockerfile:1
#
# vpn-control — multi-stage build
#
#   1. frontend   : node, `npm ci && npm run build`         -> /src/frontend/dist
#   2. chef       : rust + cargo-chef (dependency caching helper)
#   3. planner    : computes the dependency "recipe" from Cargo.toml/Cargo.lock
#   4. backend    : builds the dependencies (cached layer), then the real binary
#   5. runtime    : distroless, non-root, no shell, no package manager
#
# The AWS SDK makes a cold build slow (several minutes). Thanks to cargo-chef the
# dependency layer is rebuilt only when backend/Cargo.toml or backend/Cargo.lock change.
#
# Base images are pinned by tag. For fully reproducible, tamper-evident builds pin them by
# digest as well, e.g.:
#   docker buildx imagetools inspect rust:1-bookworm          # prints "Digest: sha256:…"
# and then build with
#   docker compose build --build-arg RUST_IMAGE=rust:1-bookworm@sha256:<digest> …
# or edit the ARG defaults below to "<image>:<tag>@sha256:<digest>". Re-pin when you update.

ARG NODE_IMAGE=node:24-bookworm-slim
ARG RUST_IMAGE=rust:1-bookworm
ARG RUNTIME_IMAGE=gcr.io/distroless/cc-debian12:nonroot
ARG CARGO_CHEF_VERSION=0.1.78

# ---------------------------------------------------------------------------------------------
# 1. Frontend (React + Vite)
# ---------------------------------------------------------------------------------------------
FROM ${NODE_IMAGE} AS frontend
WORKDIR /src/frontend
# NODE_ENV is deliberately not "production" here: the build needs devDependencies (vite, tsc).
ENV NPM_CONFIG_UPDATE_NOTIFIER=false \
    NPM_CONFIG_FUND=false \
    NPM_CONFIG_AUDIT=false
# Install exactly what the lockfile says. --ignore-scripts: no third-party install scripts run
# during the build (supply-chain hardening; esbuild/rollup ship prebuilt platform packages).
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci --ignore-scripts
COPY frontend/ ./
RUN npm run build \
 && test -f dist/index.html

# ---------------------------------------------------------------------------------------------
# 2. Rust toolchain + cargo-chef
# ---------------------------------------------------------------------------------------------
FROM ${RUST_IMAGE} AS chef
ARG CARGO_CHEF_VERSION
# cmake/clang are only needed if a crypto backend (aws-lc-sys) decides to build from source;
# cheap insurance so the build does not break on a different target/arch.
RUN apt-get update \
 && apt-get install -y --no-install-recommends cmake clang \
 && rm -rf /var/lib/apt/lists/*
RUN cargo install cargo-chef --locked --version "${CARGO_CHEF_VERSION}"
WORKDIR /src/backend

# ---------------------------------------------------------------------------------------------
# 3. Dependency recipe
# ---------------------------------------------------------------------------------------------
FROM chef AS planner
COPY backend/ ./
RUN cargo chef prepare --recipe-path recipe.json

# ---------------------------------------------------------------------------------------------
# 4. Backend build
# ---------------------------------------------------------------------------------------------
FROM chef AS backend
# Parallel rustc jobs. Each AWS SDK crate needs well over 1 GB while compiling; on a small host
# build with CARGO_BUILD_JOBS=1 (see docker-compose.yml) so they are not compiled side by side.
ARG CARGO_BUILD_JOBS=default
ENV CARGO_TERM_COLOR=never \
    CARGO_BUILD_JOBS=${CARGO_BUILD_JOBS}
COPY --from=planner /src/backend/recipe.json recipe.json
# Cached layer: all dependencies (incl. the AWS SDK). Invalidated only by Cargo.toml/Cargo.lock.
RUN cargo chef cook --release --locked --recipe-path recipe.json
COPY backend/ ./
# Embedded by the Rust provisioning module; available without a shell in the runtime image.
COPY deploy/ingress/bootstrap.sh /src/deploy/ingress/bootstrap.sh
RUN cargo build --release --locked --bin vpn-control \
 && install -D -m 0755 target/release/vpn-control /out/app/vpn-control \
 && strip /out/app/vpn-control \
 # Empty state directory, owned by the distroless "nonroot" user (65532), private.
 && install -d -m 0700 -o 65532 -g 65532 /out/data

# ---------------------------------------------------------------------------------------------
# 5. Runtime: distroless (glibc + libgcc, no shell, no package manager), non-root
# ---------------------------------------------------------------------------------------------
FROM ${RUNTIME_IMAGE} AS runtime

LABEL org.opencontainers.image.title="vpn-control" \
      org.opencontainers.image.description="Control plane for a disposable sing-box ingress on AWS (Lightsail/EC2): status, start/stop, IP rotation, subscription." \
      org.opencontainers.image.licenses="UNLICENSED" \
      org.opencontainers.image.vendor="kmode.dev" \
      org.opencontainers.image.base.name="gcr.io/distroless/cc-debian12:nonroot"

# Binary and SPA are owned by root and therefore read-only for the app user.
COPY --from=backend  /out/app/vpn-control /app/vpn-control
COPY --from=frontend /src/frontend/dist/  /app/static/
# Persistent state (a named volume is mounted here; Docker initialises an empty named volume
# with this directory's ownership, so the non-root app can write to it).
COPY --from=backend --chown=65532:65532 /out/data /data

# Non-secret defaults only. All secrets come from .env at runtime and are never baked in.
ENV BIND_ADDR=0.0.0.0:8080 \
    STATIC_DIR=/app/static \
    STATE_DIR=/data \
    LOG_FORMAT=json \
    RUST_LOG=info

USER 65532:65532
WORKDIR /app
EXPOSE 8080
VOLUME ["/data"]

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD ["/app/vpn-control", "healthcheck"]

ENTRYPOINT ["/app/vpn-control"]
CMD ["serve"]
