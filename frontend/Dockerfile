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

# Expose Next.js server port
EXPOSE 3000

# Copy necessary files from build stage
COPY --from=builder /app/package.json /app/package-lock.json ./
COPY --from=builder /app/public ./public
COPY --from=builder /app/.next ./.next
COPY --from=builder /app/node_modules ./node_modules

# Start the Next.js production server
CMD ["npm", "run", "start"]
