FROM python:3.12-slim

WORKDIR /work
COPY . .
RUN pip install --no-cache-dir .

VOLUME ["/work/out"]

CMD ["sh", "-c", "docker/demo.sh"]
