# syntax=docker/dockerfile:1
FROM node:20-alpine

WORKDIR /app

COPY package*.json ./
RUN npm ci --omit=dev && \
    npm rebuild better-sqlite3 && \
    npm cache clean --force

COPY . .

RUN addgroup -g 1001 nodejs && \
    adduser -S nodeuser -u 1001 -G nodejs && \
    chown -R nodeuser:nodejs /app

USER nodeuser

EXPOSE 3210 3737 3738