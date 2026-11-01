FROM node:20-alpine
RUN apk add --no-cache docker-cli
WORKDIR /app
COPY package.json ./
RUN npm install --omit=dev
# scan.js, scheduler.js and job-stream.js must be copied too — worker.js imports all three at
# startup, and a missing module here is an immediate crash loop rather than a
# degraded worker.
COPY worker.js scan.js scheduler.js job-stream.js ./
CMD ["node", "worker.js"]
