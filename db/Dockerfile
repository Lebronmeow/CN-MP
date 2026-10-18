FROM mysql:8.0

LABEL maintainer="Computer Networks Project Team"
LABEL description="Database Tier - MySQL 8.0 isolated in private network"

ENV MYSQL_DATABASE=student_portal
ENV MYSQL_ROOT_PASSWORD=root_super_secure_999

# Auto-execute initialization SQL script on first container start
COPY init.sql /docker-entrypoint-initdb.d/init.sql

# Only expose 3306 internally within Docker network
EXPOSE 3306
