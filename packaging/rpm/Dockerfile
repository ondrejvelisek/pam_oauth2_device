FROM centos:7

RUN yum install -y \
    gcc \
    gcc-c++ \
    libcurl-devel \
    make \
    openldap-devel \
    pam-devel \
    rpm-build \
 && yum clean all

RUN groupadd builder \
 && useradd --create-home --gid builder builder

USER builder

# This version must be identical to the version in pamoauth2device.spec
ENV PACKAGE_VERSION=0.1.1

WORKDIR /home/builder

RUN mkdir -p rpmbuild/SOURCES \
 && cd rpmbuild/SOURCES \
 && curl -L -O https://github.com/jsurkont/pam_oauth2_device/archive/v${PACKAGE_VERSION}.tar.gz

COPY --chown=builder:builder pamoauth2device.spec .

RUN rpmbuild -ba pamoauth2device.spec