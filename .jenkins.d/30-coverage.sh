#!/usr/bin/env bash
set -e

JDIR=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )
source "$JDIR"/util.sh

set -x

if [[ $JOB_NAME == *"code-coverage" ]]; then
    gcovr --object-directory=build \
          --output=build/coverage.xml \
          --exclude="$PWD/(tests)" \
          --root=. \
          --xml

    # # Generate also a detailed HTML output, but using lcov (slower, but better results)
    lcov -q -c -d . --no-external -o build/coverage-with-tests.info --rc lcov_branch_coverage=1
    lcov -q -r build/coverage-with-tests.info "$PWD/tests/*" -o build/coverage.info --rc lcov_branch_coverage=1
    genhtml build/coverage.info --output-directory build/coverage --legend --rc genhtml_branch_coverage=1
fi
