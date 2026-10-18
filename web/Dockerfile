FROM nginx:alpine

LABEL maintainer="Computer Networks Project Team"
LABEL description="Web Tier - Nginx Reverse Proxy & Static Asset Server"

# Remove default nginx config
RUN rm /etc/nginx/conf.d/default.conf

# Copy custom reverse proxy configuration
COPY nginx.conf /etc/nginx/conf.d/default.conf

# Copy frontend static assets (HTML, CSS, JS)
COPY index.html /usr/share/nginx/html/
COPY script.js /usr/share/nginx/html/
COPY style.css /usr/share/nginx/html/
COPY portal.js /usr/share/nginx/html/

# Expose HTTP port 80 for public client ingress
EXPOSE 80

CMD ["nginx", "-g", "daemon off;"]
