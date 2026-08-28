FROM node:20-alpine AS builder
WORKDIR /app
COPY package*.json ./
RUN npm install
COPY cloud-waf-proxy.ts ./

FROM node:20-alpine
WORKDIR /app
COPY package*.json ./
COPY --from=builder /app/node_modules ./node_modules
COPY --from=builder /app/cloud-waf-proxy.ts ./

# إنشاء مجلد خاص بقاعدة البيانات ومنح صلاحية الكتابة بالكامل للمستخدم node
RUN mkdir -p /app && chown -R node:node /app

EXPOSE 8080
USER node
CMD ["npx", "tsx", "cloud-waf-proxy.ts"]
