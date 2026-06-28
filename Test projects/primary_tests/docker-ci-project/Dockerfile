# VULN 1: docker-privileged (hermsec.config.docker-privileged)
# VULN 2: docker-exposed-ports (hermsec.config.docker-exposed-ports)
# VULN 3: docker-latest-tag (hermsec.config.docker-latest-tag)
# VULN 4: dockerfile-secrets (hermsec.config.dockerfile-secrets)

# Dockerfile
FROM node:latest

# VULN 1: Running as root (implicit privileged)
WORKDIR /app

# VULN 2: Exposing SSH port
EXPOSE 22
EXPOSE 80
EXPOSE 443

# VULN 3: Using latest tag
RUN apt-get update && apt-get install -y curl

# VULN 4: Hardcoded secrets in ENV
ENV DB_PASSWORD=ghazal_docker_secret_123
ENV API_KEY=ghazal-docker-api-key-abcdef123456
ENV AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY

COPY package*.json ./
RUN npm install
COPY . .
CMD ["node", "src/index.js"]
