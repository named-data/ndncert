# syntax=docker/dockerfile:1

ARG NDN_CXX_VERSION=latest
FROM ghcr.io/named-data/ndn-cxx-build:${NDN_CXX_VERSION} AS build

ARG JOBS
ARG SOURCE_DATE_EPOCH
RUN --mount=rw,target=/src <<EOF
    set -eux
    cd /src
    ./waf configure \
        --prefix=/usr \
        --libdir=/usr/lib \
        --sysconfdir=/etc \
        --localstatedir=/var \
        --sharedstatedir=/var
    ./waf build
    ./waf install
EOF


FROM ghcr.io/named-data/ndn-cxx-runtime:${NDN_CXX_VERSION} AS ndncert

COPY --link --from=build /usr/lib/libndn-cert.so.* /usr/lib/
COPY --link --from=build /usr/bin/ndncert-ca-server /usr/bin/
COPY --link --from=build /usr/bin/ndncert-ca-status /usr/bin/
COPY --link --from=build /usr/bin/ndncert-send-email-challenge /usr/bin/
COPY --link --from=build /usr/bin/ndncert-client /usr/bin/

RUN apt-get install -Uy --no-install-recommends \
        python3 \
    && apt-get distclean

ENV HOME=/config
VOLUME /config
VOLUME /etc/ndncert
VOLUME /run/nfd

ENTRYPOINT ["/usr/bin/ndncert-ca-server"]
CMD ["-c", "/config/ca.conf"]
