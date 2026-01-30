#!/bin/bash
CWD=$PWD
make -j8
# We need a TTY, otherswise the tests will not finish. So ssh to self.
ssh -tt localhost "cd $CWD && make check"
