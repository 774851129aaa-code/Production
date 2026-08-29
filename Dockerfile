FROM node:20-slim AS builder

WORKDIR /app

COPY package*.json ./
RUN npm install

COPY cloud-waf-proxy.ts ./
COPY index.html ./

FROM node:20-slim

WORKDIR /app

COPY package*.json ./
COPY --from=builder /app/node_modules ./node_modules
COPY --from=builder /app/cloud-waf-proxy.ts ./
COPY --from=builder /app/index.html ./

RUN chown -R node:node /app

EXPOSE 8080

USER node

CMD ["npx", "tsx", "cloud-waf-proxy.ts"]
