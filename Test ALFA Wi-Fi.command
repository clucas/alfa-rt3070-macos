#!/bin/zsh
set -u
umask 077
cd -- "${0:A:h}"
mkdir -p build
print 'This test uses the ALFA without switching your Mac away from its current connection.'
print 'Choose your network from the list. Its password stays in memory and is not saved.'
print ''
.venv/bin/python -m alfa_rt3070.cli connect --check 2>&1 | /usr/bin/tee build/connection-test.log
print ''
read '?Press Return to close.'
