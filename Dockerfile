FROM python:3.5-alpine
LABEL maintainer="Mostafa Hussein <mostafa.hussein91@gmail.com>"
RUN apk add --no-cache gcc musl-dev libxml2-dev libxslt-dev nmap openssl
RUN pip install raccoon-scanner
RUN adduser -D raccoon
USER raccoon
ENTRYPOINT ["raccoon"]
CMD ["--help"]
