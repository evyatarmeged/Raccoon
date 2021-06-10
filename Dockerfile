FROM python:3.5-alpine
LABEL maintainer="Mostafa Hussein <mostafa.hussein91@gmail.com>"
RUN apk add --no-cache gcc musl-dev libxml2-dev libxslt-dev nmap nmap-scripts openssl
RUN pip install raccoon-scanner
RUN groupadd -r -g 5055 raccoon && useradd -r -u 5055 -g raccoon raccoon
USER raccoon
ENTRYPOINT ["raccoon"]
CMD ["--help"]
