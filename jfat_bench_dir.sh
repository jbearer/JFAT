#!/usr/bin/env bash

set -e

source "jfat.sh"

start

for i in `seq 1000`; do
    mkdir "$MNT/dir$i"
    ls "$MNT" > /dev/null
    ls "$MNT/dir$i" > /dev/null
done

path="$MNT/dir1"
for i in `seq 2 500`; do
    sub="$path/dir$i"
    mkdir "$sub"
    ls "$path" > /dev/null
    ls "$sub" > /dev/null
    path="$sub"
done

stop
