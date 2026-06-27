FROM python:3.13-alpine AS builder

RUN pip3 install poetry==2.1.3
RUN apk update && apk upgrade

ARG installdir=/collector
ADD . ${installdir}
RUN cd ${installdir} && poetry build

FROM python:3.13-alpine AS runner

ARG installdir=/collector
ARG PYOAEV_GIT_BRANCH_OVERRIDE

COPY --from=builder ${installdir} ${installdir}
RUN cd ${installdir}/dist && pip3 install --no-cache-dir "$(ls *.whl)[prod]"

RUN if [[ ${PYOAEV_GIT_BRANCH_OVERRIDE} ]] ; then \
        echo "Forcing specific version of client-python" && \
        apk add --no-cache git && \
        pip install pip3-autoremove && \
        pip-autoremove pyoaev -y && \
        pip install git+https://github.com/OpenAEV-Platform/client-python@${PYOAEV_GIT_BRANCH_OVERRIDE} ; \
    fi

WORKDIR ${installdir}

CMD ["python3", "-m", "lakera_guard.openaev_lakera_guard"]
