# Pin both stages to the verified multi-platform manifest digest.
FROM python:3.12.16-slim-trixie@sha256:4840d514c583a4d3d8cad3940e68dee6f0f6f3635c12fcd0a3d74c21a5b93a54 AS build
WORKDIR /build
COPY pyproject.toml uv.lock README.md ./
COPY chinescan ./chinescan
RUN python -m pip install --no-cache-dir uv==0.13.5 build==1.6.1 \
    && uv export --frozen --no-dev --no-emit-project --format requirements-txt --output-file /build/requirements.txt \
    && python -m build --wheel
COPY alembic.ini ./alembic.ini
COPY migrations ./migrations

FROM python:3.12.16-slim-trixie@sha256:4840d514c583a4d3d8cad3940e68dee6f0f6f3635c12fcd0a3d74c21a5b93a54 AS runtime
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
RUN apt-get update \
    && apt-get install --no-install-recommends --yes \
        zlib1g=1:1.3.dfsg+really1.3.1-1+deb13u1 \
    && rm -rf /var/lib/apt/lists/*
RUN groupadd --system chinescan && useradd --system --gid chinescan --create-home chinescan
WORKDIR /app
COPY --from=build /build/dist/*.whl /tmp/
COPY --from=build /build/requirements.txt /tmp/requirements.txt
RUN python -m pip install --no-cache-dir --require-hashes -r /tmp/requirements.txt \
    && python -m pip install --no-cache-dir --no-deps /tmp/*.whl \
    && rm /tmp/*.whl /tmp/requirements.txt
COPY --from=build /build/alembic.ini /usr/local/lib/python3.12/site-packages/alembic.ini
COPY --from=build /build/migrations /usr/local/lib/python3.12/site-packages/migrations
USER chinescan
ENTRYPOINT ["chinescan"]
CMD ["--help"]
