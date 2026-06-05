# --- BUILD STAGE ---
FROM node:20-alpine AS builder
WORKDIR /app

# Copy dependency manifests
COPY package.json package-lock.json ./

# Install all dependencies (including devDependencies for build)
RUN npm ci

# Copy source code and build config
COPY tsconfig.json next.config.mjs eslint.config.mjs postcss.config.mjs ./
COPY src ./src
COPY public ./public

# Build the Next.js app
ENV NEXT_TELEMETRY_DISABLED=1
RUN npm run build

# --- PRODUCTION RUNTIME ---
FROM node:20-alpine AS runner
WORKDIR /app

ENV NODE_ENV=production
ENV PORT=3000
ENV NEXT_TELEMETRY_DISABLED=1

# Expose static site port
EXPOSE 3000

RUN npm install -g serve

# Copy exported static bundle from build stage
COPY --from=builder /app/out ./out

# Serve the exported site
CMD ["serve", "-s", "out", "-l", "3000"]
