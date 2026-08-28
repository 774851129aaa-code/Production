FROM node:20-alpine AS builder
WORKDIR /app
COPY package*.json ./
RUN npm install
COPY cloud-waf-proxy.ts ./

FROM node:20-alpine
WORKDIR /app
COPY package*.json ./
RUN npm install --production
COPY --from=builder /app/cloud-waf-proxy.ts ./

EXPOSE 8080
USER node
CMD ["npx", "tsx", "cloud-waf-proxy.ts"]
