# VULN (Security Misconfiguration): runs as root, base tag not pinned to
# digest — intentional for benchmark realism.
FROM node:18

WORKDIR /app
COPY package.json ./
RUN npm install --no-audit --no-fund || true
COPY . .

ENV NODE_ENV=development
EXPOSE 8085

CMD ["node", "server.js"]
