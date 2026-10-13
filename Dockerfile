FROM python:3.12-slim

LABEL org.opencontainers.image.title="Kong HTTP Log Viewer"
LABEL org.opencontainers.image.description="Viewer for Kong Gateway and AI Gateway http-log traffic"

WORKDIR /app

# install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# copy app & templates
# Glob rather than naming files, so adding a module doesn't need a Dockerfile change
COPY *.py ./
COPY templates ./templates

# create data directory and expose as volume
ENV DB_DIR=/app/data
RUN mkdir -p $DB_DIR && chmod 777 $DB_DIR
VOLUME [ "/app/data" ]

# expose new port
EXPOSE 5015

CMD ["python", "app.py"]