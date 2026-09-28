# Static site image for apps.lan (codepilot-cl/homelab#34). Only the files the page loads are
# copied, listed explicitly (homelab#62): a new file in the repo stays out of the image until it
# is added here. .dockerignore is an allowlist of the same files, which also keeps the context small.
FROM nginx:1.29-alpine
COPY index.html /usr/share/nginx/html/
COPY assets/ /usr/share/nginx/html/assets/
