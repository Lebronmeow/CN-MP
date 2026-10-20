FROM mysql:8.0

# Install iproute and procps using microdnf (Oracle Linux base) for multi-tier routing
RUN microdnf install -y iproute procps-ng && microdnf clean all

COPY my.cnf /etc/mysql/conf.d/shopledger.cnf
RUN chmod 644 /etc/mysql/conf.d/shopledger.cnf
COPY init.sql /docker-entrypoint-initdb.d/01-init.sql
COPY entrypoint.sh /custom-entrypoint.sh
RUN chmod +x /custom-entrypoint.sh

EXPOSE 3306

ENTRYPOINT ["/custom-entrypoint.sh"]
