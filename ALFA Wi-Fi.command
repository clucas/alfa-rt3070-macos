#!/bin/zsh
set -u
cd -- "${0:A:h}"
print 'ALFA RT3070 — experimental native Mac driver'
print ''
print '1. Scan nearby Wi-Fi networks'
print '2. Test a connection (keeps your Mac on its current connection)'
print '3. Use the ALFA for IPv4 internet access'
print ''
read 'selection?Choose 1, 2, or 3: '
case "$selection" in
  1) .venv/bin/python -m alfa_rt3070.cli scan ;;
  2) .venv/bin/python -m alfa_rt3070.cli connect --check ;;
  3)
    print 'macOS needs your login password to create a temporary network interface.'
    print 'Then select your Wi-Fi network and enter its password.'
    print 'Press Control-C when you want to switch back.'
    /usr/bin/sudo -- "$PWD/.venv/bin/python" -m alfa_rt3070.cli connect --prefer
    ;;
  *) print 'No action selected.' ;;
esac
print ''
read '?Press Return to close.'
