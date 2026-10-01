# Node.js LTS multi-stage production image
FROM node:20-alpine AS builder

WORKDIR /app

# Copiar configuraciones y dependencias
COPY package.json tsconfig.json package-lock.json* ./

# Instalar dependencias para compilar (funciona tanto si hay package-lock como si no)
RUN if [ -f package-lock.json ]; then npm ci; else npm install; fi

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
RUN if [ -f package-lock.json ]; then npm ci --omit=dev; else npm install --omit=dev; fi

# Copiar dist compilado y plantillas views
COPY --from=builder /app/dist ./dist
COPY --from=builder /app/views ./views

EXPOSE 3000

CMD ["node", "dist/server.js"]
