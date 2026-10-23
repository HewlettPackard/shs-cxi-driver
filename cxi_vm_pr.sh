#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
#
# Stop at the first failing gate so its exit status is what the job reports.
set -e
git checkout -b rebase-test-branch

# Build only first as it's fast
_build='set -e; git log -1 && make check-ai-context && make check-abi && make clean && make -j8'
git rebase `git merge-base origin/main HEAD` --exec "$_build"

# Then build and test
# We need a TTY, otherswise the tests will not finish. So ssh to self.
git rebase `git merge-base origin/main HEAD` --exec 'set -e; CWD=$PWD; git log -1 && make clean && make -j8 && ssh -tt localhost "cd $CWD && make check"'
