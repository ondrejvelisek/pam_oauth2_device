# pam_oauth2_device version
%define _version 0.1.1
%define _lib /lib64


Name:    pamoauth2device
Version: %{_version}
Release: 1%{?dist}
Summary: PAM module for OAuth 2.0 Device flow
License: Apache-2.0
URL:     https://github.com/jsurkont/pam_oauth2_device/tree/c_implementation
Source0: https://github.com/jsurkont/pam_oauth2_device/archive/v%{_version}.tar.gz


# List of build-time dependencies:
BuildRequires: gcc
BuildRequires: gcc-c++
BuildRequires: make
BuildRequires: libcurl-devel
BuildRequires: openldap-devel
BuildRequires: pam-devel


# List of runtime dependencies:
Requires: curl
Requires: openldap-clients


%description
PAM module that allows authentication against external OpenID Connect
identity provider using OAuth 2.0 Device Flow.


%prep
%setup -q -n pam_oauth2_device-%{_version}


%build
make


%install
mkdir -p ${RPM_BUILD_ROOT}%{_lib}/security
mkdir -p ${RPM_BUILD_ROOT}%{_sysconfdir}/pam_oauth2_device
install pam_oauth2_device.so ${RPM_BUILD_ROOT}%{_lib}/security
cp config_template.json ${RPM_BUILD_ROOT}%{_sysconfdir}/pam_oauth2_device/config.json


%check
# no test.


%files
%doc LICENSE README.md
%{_lib}/security/pam_oauth2_device.so
%{_sysconfdir}/pam_oauth2_device/config.json


%changelog
* Thu Nov 21 2019 Jaroslaw Surkont <jaroslaw.surkont@unibas.ch> - 0.1.1-1
- Add username_attribute to config (#7)
- Add client authentication to device endpoint (#6)

* Fri Aug 09 2019 Jaroslaw Surkont <jaroslaw.surkont@unibas.ch> - 0.1.0-1
- first build for pamoauth2device.
