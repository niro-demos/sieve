# ⚠️ Intentionally vulnerable smoke-test target. Build/run on localhost or CI
#    only — never deploy or expose to the internet.
FROM python:3.12-slim
RUN pip install --no-cache-dir flask==3.0.3
WORKDIR /app
COPY app.py /app/app.py
EXPOSE 5000
CMD ["python", "app.py"]
