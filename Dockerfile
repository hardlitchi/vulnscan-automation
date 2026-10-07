# Web 画面つきの vulnscan。スキャナ（nmap / nuclei / ZAP）はホストの Docker で起動する。
FROM docker:27-cli AS dockercli

FROM python:3.12-slim
COPY --from=dockercli /usr/local/bin/docker /usr/local/bin/docker
WORKDIR /app
COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install --no-cache-dir ".[web]"
ENTRYPOINT ["vulnscan"]
CMD ["--help"]
