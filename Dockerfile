# Static site image for apps.lan (codepilot-cl/homelab#34). Only the files the
# page loads are copied (see .dockerignore): no .git, docs, tests or README.
FROM nginx:1.29-alpine
COPY . /usr/share/nginx/html
