FROM docker.io/freeipa/freeipa-server:fedora-41

USER root

RUN dnf install -y \
    @development-tools gcc make autoconf automake libtool \
    krb5-devel libtalloc-devel libtevent-devel \
    samba-devel openldap-devel popt-devel nspr-devel nss-devel \
    libsss_idmap-devel libunistring-devel python3-devel \
    git wget && \
    dnf clean all

COPY schema/99trust-level.ldif /tmp/99trust-level.ldif
COPY patches/ipa-kdb-trust-level.patch /tmp/ipa-kdb-trust-level.patch
COPY freeipa-plugin/trustlevel.py /tmp/trustlevel.py
COPY docker/setup-inside-container.sh /tmp/setup-inside-container.sh

RUN chmod +x /tmp/setup-inside-container.sh

ENTRYPOINT ["/sbin/init"]
