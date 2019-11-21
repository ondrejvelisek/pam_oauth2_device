#!/bin/bash

NAME=pamoauth2device
VERSION=0.1.1
URL_REPO=https://github.com/jsurkont/pam_oauth2_device
BUILD_DIR=${NAME}-${VERSION}

curl -L ${URL_REPO}/archive/v${VERSION}.tar.gz -o ${NAME}_${VERSION}.orig.tar.gz
mkdir ${BUILD_DIR}
tar -xzf ${NAME}_${VERSION}.orig.tar.gz -C ${BUILD_DIR} --strip-components 1
cp -r debian ${BUILD_DIR}
cd ${BUILD_DIR}
debuild --force-sign
