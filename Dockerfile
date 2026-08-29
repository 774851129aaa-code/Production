FROM node:20-slim AS builder

WORKDIR /app

COPY package*.json ./

RUN npm install

# نسخ ملفات المشروع المطلوبة
COPY cloud-waf-proxy.ts ./
COPY index.html ./

FROM node:20-slim

WORKDIR /app

COPY package*.json ./
COPY --from=builder /app/node_modules ./node_modules
COPY --from=builder /app/cloud-waf-proxy.ts ./
COPY --from=builder /app/index.html ./

RUN chown -R node:node /app

USER node

# Render يحدد PORT تلقائياً
CMD ["npm", "start"]
