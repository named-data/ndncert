#!/usr/bin/env bash
set -eo pipefail

if [[ -z $DISABLE_ASAN ]]; then
    ASAN="--with-sanitizer=address"
fi
if [[ $JOB_NAME == *code-coverage ]]; then
    COVERAGE="--with-coverage"
fi

set -x

if [[ $JOB_NAME != *code-coverage && $JOB_NAME != *limited-build ]]; then
    # Build in release mode with tests
    ./waf --color=yes configure --with-tests
    ./waf --color=yes build

    # Cleanup
    ./waf --color=yes distclean

    # Build in release mode without tests
    ./waf --color=yes configure
    ./waf --color=yes build

    # Cleanup
    ./waf --color=yes distclean
fi

# Build in debug mode with tests
./waf --color=yes configure --debug --with-tests $ASAN $COVERAGE
./waf --color=yes build

# Install
sudo ./waf --color=yes install

if [[ $ID_LIKE == *linux* ]]; then
    if [[ $(uname -m) == x86_64 && -d /usr/lib64 ]]; then
        sudo tee /etc/ld.so.conf.d/ndn.conf >/dev/null <<< /usr/local/lib64
    fi
    sudo ldconfig
fi
