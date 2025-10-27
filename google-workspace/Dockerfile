FROM python:3.14-alpine AS builder

# poetry version available on Ubuntu 24.04
RUN pip3 install poetry==2.1.3

RUN apk update && apk upgrade

ARG installdir=/collector
ADD . ${installdir}
RUN cd ${installdir} && poetry build

FROM python:3.14-alpine AS runner

ARG installdir=/collector
COPY --from=builder ${installdir} ${installdir}
RUN cd ${installdir}/dist && pip3 install --no-cache-dir "$(ls *.whl)[prod]"

# necessary for icon location
WORKDIR ${installdir}

CMD ["python3", "-m", "google_workspace.openaev_google_workspace"]
