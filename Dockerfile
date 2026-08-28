FROM node:20-alpine AS builder
WORKDIR /app
COPY package*.json ./
RUN npm install
COPY cloud-waf-proxy.ts ./
# نسخ ملف الواجهة أيضاً في مرحلة البناء إن أردت أو مباشرة في المرحلة النهائية
COPY index.html ./

FROM node:20-alpine
WORKDIR /app
COPY package*.json ./
COPY --from=builder /app/node_modules ./node_modules
COPY --from=builder /app/cloud-waf-proxy.ts ./
# نسخ ملف index.html من مرحلة البناء إلى الحاوية النهائية
COPY --from=builder /app/index.html ./

# إنشاء مجلد خاص بقاعدة البيانات ومنح صلاحية الكتابة بالكامل للمستخدم node
RUN mkdir -p /app && chown -R node:node /app

EXPOSE 8080
USER node
CMD ["npx", "tsx", "cloud-waf-proxy.ts"]
