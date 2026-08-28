FROM node:20-alpine AS builder
WORKDIR /app
COPY package*.json ./
RUN npm install
COPY cloud-waf-proxy.ts ./

FROM node:20-alpine
WORKDIR /app
COPY package*.json ./
# نسخ الحزم المثبتة بالكامل من مرحلة البناء لضمان توفر أدوات التشغيل مثل tsx
COPY --from=builder /app/node_modules ./node_modules
COPY --from=builder /app/cloud-waf-proxy.ts ./

EXPOSE 8080
USER node
CMD ["npx", "tsx", "cloud-waf-proxy.ts"]
