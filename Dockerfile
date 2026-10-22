# Node.js LTS multi-stage production image
FROM node:20-alpine AS builder

WORKDIR /app

# Copiar configuraciones y dependencias
COPY package.json tsconfig.json package-lock.json* ./

# Instalar dependencias para compilar de forma robusta
RUN npm install

# Copiar código fuente y compilar a dist/
COPY . .
RUN npm run build

# Runtime limpio y liviano para producción
FROM node:20-alpine AS runner

WORKDIR /app

ENV NODE_ENV=production \
    PORT=3000

COPY package.json package-lock.json* ./

# Instalar sólo dependencias de producción
RUN npm install --omit=dev

# Copiar dist compilado (backend en dist/ y frontend React SPA en dist/client/)
COPY --from=builder /app/dist ./dist
COPY results_baseline ./results_baseline

EXPOSE 3000

CMD ["node", "dist/server.js"]
