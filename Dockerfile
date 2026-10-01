# Node.js LTS multi-stage production image
FROM node:20-alpine AS builder

WORKDIR /app

# Instalar todas las dependencias para compilar TypeScript
COPY package*.json tsconfig.json ./
RUN npm ci

# Copiar código fuente y compilar a dist/
COPY . .
RUN npm run build

# Runtime limpio y liviano (sin devDependencies)
FROM node:20-alpine AS runner

WORKDIR /app

ENV NODE_ENV=production \
    PORT=3000

COPY package*.json ./
RUN npm ci --only=production

# Copiar dist compilado y plantillas views
COPY --from=builder /app/dist ./dist
COPY --from=builder /app/views ./views

EXPOSE 3000

CMD ["node", "dist/server.js"]
