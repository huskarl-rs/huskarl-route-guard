FROM nginx:1.28.0@sha256:552e7481ca93ffccd046aa658dbbed22caefbc09c66fa7cd247cbb90b8a5c609
ENV NGINX_ENVSUBST_OUTPUT_DIR=/etc/nginx
ENV NGINX_ENVSUBST_FILTER="^(UPSTREAM|FORWARD_TARGET)$"
COPY nginx.conf.template /etc/nginx/templates/nginx.conf.template
