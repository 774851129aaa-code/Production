FROM node:20-alpine AS builder

WORKDIR /app

COPY package*.json ./

RUN npm install

COPY cloud-waf-proxy.ts ./
COPY index.html ./


FROM node:20-alpine

WORKDIR /app

COPY package*.json ./
COPY --from=builder /app/node_modules ./node_modules
COPY --from=builder /app/cloud-waf-proxy.ts ./
COPY --from=builder /app/index.html ./

RUN chown -R node:node /app

EXPOSE 8080

USER node

CMD ["./node_modules/.bin/tsx", "cloud-waf-proxy.ts"]
