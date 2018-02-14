#!/bin/sh
#
# build.sh
# Build a project
# By J. Stuart McMurray
# Created 20160221
# Last Modified 20160625

set -e

PROG=$(basename $(pwd))

go vet

for GOOS in windows linux openbsd darwin; do
        for GOARCH in 386 amd64; do
                export GOOS GOARCH
                N="$PROG.$GOOS.$GOARCH"
                # Windows is special...
                if [ "windows" == $GOOS ]; then
                        go build -o "$N.exe"
                        ls -l "$N.exe"
                        go build -o "$N.nogui.exe" -ldflags "-H windowsgui"
                        ls -l "$N.nogui.exe"
                else
                        go build -o "$N"
                        ls -l $N
                fi
        done
done

echo Done.
