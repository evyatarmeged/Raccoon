FROM python:3.8-alpine

LABEL maintainer="Evyatar Meged <evyatarmeged@gmail.com>"
LABEL dockerfile-creator="Mostafa Hussein <mostafa.hussein91@gmail.com>"

RUN addgroup -S raccoon && \
    adduser -S raccoon -G raccoon

RUN apk add --no-cache gcc musl-dev libxml2-dev libxslt-dev nmap nmap-scripts openssl

USER raccoon
WORKDIR /home/raccoon
RUN pip install raccoon-scanner

ENV PATH=/home/raccoon/.local/bin:${PATH}

ENTRYPOINT ["raccoon"]
CMD ["--help"]
