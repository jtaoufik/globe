FROM python:3.12-slim
WORKDIR /app
RUN pip install --no-cache-dir requests PyJWT cryptography
# GeoNames cities (free) baked into the image so a restart never waits on a download.
ADD https://download.geonames.org/export/dump/cities15000.zip /tmp/cities15000.zip
RUN python -c "import zipfile; zipfile.ZipFile('/tmp/cities15000.zip').extract('cities15000.txt', '/app')" && rm /tmp/cities15000.zip
COPY pull.py server.py ./
COPY static ./static
ENV PORT=8080
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8080/healthz').status==200 else 1)"
CMD ["python", "server.py"]
