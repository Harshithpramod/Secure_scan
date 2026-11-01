# The fixer only makes HTTPS calls — no git, no CodeQL, no semgrep — so this
# image is a few megabytes rather than the runner's ~850MB.
#
# BUILD FROM sandbox/, not sandbox/fixer/: the fixer re-scans its own patch with
# the scanner's code in worker/, so the build context has to include it.
#   docker build -t pentestai/fixer:latest -f fixer/Dockerfile .
#
# The files keep the repo's relative layout (fixer/ next to worker/) so the
# `../worker/scan.js` imports resolve identically here and in a local checkout.
FROM node:20-alpine
WORKDIR /app
# Root package.json marks everything under /app as ES modules, including
# worker/, which has no package.json of its own in this image.
COPY fixer/package.json ./package.json
COPY fixer/package.json fixer/fixer.js ./fixer/
COPY worker/scan.js worker/fix-gate.js ./worker/
# Runs as uid 1000 (node) to match the --user 1000:1000 the worker enforces.
USER node
CMD ["node", "fixer/fixer.js"]
