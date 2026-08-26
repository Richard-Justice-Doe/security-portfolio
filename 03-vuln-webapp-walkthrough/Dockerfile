# VULNERABLE BY DESIGN — LAB USE ONLY, DO NOT DEPLOY PUBLICLY
#
# This image exists only so the intentionally weak campus-portal lab
# can run in an isolated local container. Do not publish the image,
# do not map it to a public IP, and do not point scanners at anything
# you do not own.
#
# Build:  docker build -t campus-portal-vuln-lab .
# Run:    docker run --rm -p 127.0.0.1:5002:5002 campus-portal-vuln-lab

FROM python:3.12-slim

LABEL org.opencontainers.image.title="campus-portal-vuln-lab"
LABEL org.opencontainers.image.description="VULNERABLE BY DESIGN — LAB USE ONLY, DO NOT DEPLOY PUBLICLY"
LABEL lab.warning="VULNERABLE BY DESIGN — LAB USE ONLY, DO NOT DEPLOY PUBLICLY"

WORKDIR /app
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

COPY vulnerable/ /app/

ENV LAB_WARNING="VULNERABLE BY DESIGN — LAB USE ONLY, DO NOT DEPLOY PUBLICLY"
ENV FLASK_RUN_HOST=0.0.0.0
EXPOSE 5002

# Bind all interfaces *inside* the container so Docker port-publish works.
# Host publish is 127.0.0.1:5002 — see README. Do not use -p 0.0.0.0:5002:5002.
CMD ["python", "app.py"]
