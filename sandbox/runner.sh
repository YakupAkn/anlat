#!/bin/sh
# Runs /sample/target inside strace and writes the trace to /out/trace.log
cp /sample/target /tmp/target && chmod +x /tmp/target
cd /home/user
timeout "${ANLAT_TIMEOUT:-30}" strace -f -qq -s 256 \
  -e trace=file,network,process,read,write \
  -o /out/trace.log /tmp/target >/out/stdout.log 2>&1
echo "exit=$?" > /out/exit.txt
