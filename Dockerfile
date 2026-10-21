# 内容安全预检智能体：容器镜像
#
# 构建（在 call_safety_review 目录下执行，vendor/ 已含发行目录提供的两个 wheel）：
#   docker build -t content-safety-review:1.0.0 .
#
# 运行（HTTP 审查服务，默认）：
#   docker run --rm -p 8080:8080 -e CSR_AUTH_TOKEN=change-me content-safety-review:1.0.0
#
# 运行（ACPs Partner，需要 Registry / CA / Discovery 与凭据）：
#   docker run --rm -p 8080:8080 -p 8443:8443 \
#     -e ACPS_REGISTRY_URL=... -e ACPS_CA_URL=... -e ACPS_DISCOVERY_URL=... \
#     -e ACPS_PUBLIC_ENDPOINT=... -e ACPS_ORGANIZATION=... -e ACPS_COUNTRY_CODE=CN \
#     -e ACPS_USERNAME=... -e ACPS_PASSWORD=... -e OPENAI_MODEL=... -e OPENAI_API_KEY=... \
#     -v csr-acps-state:/var/lib/content-safety-review \
#     content-safety-review:1.0.0 acps

FROM python:3.12-slim

# wit 支持 CPython 3.12 / 3.13 / 3.14；此处固定 3.12 slim 作为最小可用基座。
LABEL org.opencontainers.image.title="content-safety-review" \
      org.opencontainers.image.description="内容安全预检智能体（wit 2.1.0 / acps-sdk 2.2.0）" \
      org.opencontainers.image.version="1.0.0" \
      org.opencontainers.image.licenses="Proprietary"

ARG CSR_UID=10001
ARG CSR_GID=10001

# 离线构建用：把 wit 的运行时依赖 wheel 一并放进 vendor/，然后
#   docker build --build-arg PIP_INDEX_ARGS="--no-index --find-links=/tmp/wheels" .
ARG PIP_INDEX_ARGS=

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    CSR_HTTP_HOST=0.0.0.0 \
    CSR_HTTP_PORT=8080 \
    CSR_LOG_LEVEL=INFO \
    CSR_MAX_BODY_BYTES=1048576 \
    CSR_STATE_DIR=/var/lib/content-safety-review \
    ACPS_WORKSPACE=/var/lib/content-safety-review/acps

WORKDIR /app

# 1) 安装发行目录提供的两个 wheel：必须先装 acps-sdk，再装 wit-framework（版本严格锁定）。
#    其余运行时依赖（openai / httpx / pydantic / cryptography / jcs 等）由 pip 从索引解析。
COPY vendor/ /tmp/wheels/
RUN python -m pip install --no-cache-dir ${PIP_INDEX_ARGS} /tmp/wheels/acps_sdk-2.2.0-py3-none-any.whl \
    && python -m pip install --no-cache-dir ${PIP_INDEX_ARGS} \
         /tmp/wheels/wit_framework-2.1.0-cp312.cp313.cp314-none-any.whl \
    && rm -rf /tmp/wheels

# 2) 安装应用到 /app，并核对导入来源（对应开发指导书 2.6 的导入核对步骤）。
COPY pyproject.toml README.md ./
COPY call_safety_review/ ./call_safety_review/
COPY examples/ ./examples/
RUN python -c "from importlib.metadata import version; import acps_sdk, wit; print('acps-sdk', version('acps-sdk'), acps_sdk.__file__); print('wit', version('wit-framework'), wit.__file__)"

# 3) 构建期自检：Agent 装配必须无 error 级诊断（inspect 失败即构建失败）。
RUN python -m call_safety_review inspect --ensure-ascii --out /tmp/inspect.json

# 4) 构建期自检：阻断场景必须给出阻断结论（CLI 退出码 3 = 需确认或阻断）。
RUN python -m call_safety_review review \
        --request examples/sample_requests.json --name block_prompt_injection --out /tmp/block.json \
    ; test $? -eq 3

# 5) 非 root 运行；状态目录留给 ACPs 模式的身份材料与任务存储。
RUN groupadd --gid "${CSR_GID}" csr \
    && useradd --uid "${CSR_UID}" --gid "${CSR_GID}" --create-home --shell /usr/sbin/nologin csr \
    && mkdir -p "${CSR_STATE_DIR}" \
    && chown -R csr:csr /app "${CSR_STATE_DIR}"

USER csr

EXPOSE 8080 8443
STOPSIGNAL SIGTERM

# 探针走 shell 形式，以便跟随 CSR_HTTP_PORT；关闭内嵌 HTTP（--http-port 0）时请覆盖本探针。
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD python -m call_safety_review health --port "${CSR_HTTP_PORT:-8080}" || exit 1

# 入口固定为模块调用，因此 `docker run <image> acps`、`docker run <image> review --request -`
# 都能直接工作；需要进容器排查时用 `docker run --entrypoint sh -it <image>`。
ENTRYPOINT ["python", "-m", "call_safety_review"]
CMD ["serve-http", "--host", "0.0.0.0", "--port", "8080"]
