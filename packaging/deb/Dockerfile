FROM ubuntu:18.04

RUN apt-get update && apt-get install -y \
    build-essential \
    debhelper \
    devscripts \
    libcurl4-openssl-dev \
    libldap2-dev \
    libpam0g-dev \
 && rm -rf /var/lib/apt/lists/*

RUN groupadd builder \
 && useradd --create-home --gid builder builder

USER builder

ENV PACKAGE_NAME=pamoauth2device \
    PACKAGE_VERSION=0.1.1 \
    PACKAGE_URL=https://github.com/jsurkont/pam_oauth2_device

WORKDIR /home/builder

COPY --chown=builder:builder debian debian

RUN curl -L ${PACKAGE_URL}/archive/v${PACKAGE_VERSION}.tar.gz -o ${PACKAGE_NAME}_${PACKAGE_VERSION}.orig.tar.gz \
 && mkdir build \
 && tar -xzf ${PACKAGE_NAME}_${PACKAGE_VERSION}.orig.tar.gz -C build --strip-components 1 \
 && cp -r debian build \
 && cd build \
 && debuild
