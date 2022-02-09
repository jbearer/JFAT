#! /usr/bin/env bash

source "jfat.sh"

function info()
{
    echo "$@"
}

function error()
{
    echo "$@"
}

function stat_avail()
{
    df -B1 --output=avail "$1" | sed 1d
}

function read_byte_range()
{
    f="$1"
    begin=`expr "$2" + 1`
    end=`expr "$3" + 1`

    tail -c +$begin "$f" | head -c `expr $end - $begin`
}

function silence()
{
    "$@" > /dev/null 2>&1
}

function assert_ok()
{
    "$@"
    status=$?
    if [[ $status != 0 ]]; then
        error "Command \`$@\` failed with error $status"
        crash
        exit 1
    fi
}

function assert_not_ok()
{
    if silence "$@"; then
        error "Command \`$@\` succeeded, but failure was expected"
        crash
        exit 1
    fi
}

function assert_eq()
{
    e1="$1"
    e2="$2"

    if [[ "$e1" != "$e2" ]]; then
        error "Expected $e1 to equal $e2"
        crash
        exit 1
    fi
}

function assert_ne()
{
    e1="$1"
    e2="$2"

    if [[ "$e1" == "$e2" ]]; then
        error "Expected $e1 not to equal $e2"
        crash
        exit 1
    fi
}

function assert_lt()
{
    e1="$1"
    e2="$2"

    if [[ $e1 -ge $e2 ]]; then
        error "Expected $e1 to be less than $e2"
        crash
        exit 1
    fi
}

info "Basic functionality:"

start

info "  - wide directory tree..."

    for i in `seq 100`; do
        assert_ok mkdir "$MNT/dir$i"
    done

    # Read it back
    i=1
    for f in `ls -1 --sort=time "$MNT" | tac`; do
        assert_eq "$f" "dir$i"
        let i=i+1
    done
    assert_eq "$i" 101

info "    ...ok"
info "  - deep directory tree..."

    path="$MNT/dir1"
    for i in `seq 2 100`; do
        path+="/dir$i"
        assert_ok mkdir "$path"
    done

    # Read it back
    i=1
    path="$MNT"
    for f in `find "$MNT/dir1" -name dir\*`; do
        path+="/dir$i"
        assert_eq "$path" "$f"
        let i=i+1
    done
    assert_eq 101 "$i"

info "    ...ok"
info "  - file truncation"

    for size in 0 4095 4096 4097 1234567; do
        truncate -s $size /tmp/zeros$size
        truncate -s $size "$MNT/file$size"

        assert_eq $size "`stat -c "%s" "$MNT/file$size"`"
        assert_eq "`cat /tmp/zeros$size`" "`cat "$MNT/file$size"`"
    done

info "    ...ok"
info "  - create not existing"

    rm -f "$MNT/scratch"
    touch "$MNT/scratch"
    assert_ok silence stat "$MNT/scratch"

info "    ...ok"
info "  - create existing"

    touch "$MNT/scratch"
    assert_ok touch "$MNT/scratch"
    assert_ok silence stat "$MNT/scratch"

info "    ...ok"
info "  - write and read back"

    echo -e "foo\nbar" > "$MNT/scratch"
    assert_eq foo$'\n'bar "`cat "$MNT/scratch"`"

info "    ...ok"
info "  - random read"

    echo -e "foo\nbar" > "$MNT/scratch"

    assert_eq $'\n'ba "`read_byte_range "$MNT/scratch" 3 6`"
    assert_eq $'\n'bar "`read_byte_range "$MNT/scratch" 3 77`"

info "    ...ok"
info "  - big random write"

    data="`head -c 10000 /dev/urandom`"
    echo "$data" > "$MNT/scratch"
    assert_eq "$data" "`cat "$MNT/scratch"`"

info "    ...ok"
info "  - append"

    echo "foo" > "$MNT/scratch"
    echo "bar" >> "$MNT/scratch"
    assert_eq foo$'\n'bar "`cat "$MNT/scratch"`"

info "    ...ok"
info "  - overwrite no extend"

    echo "bug" > "$MNT/scratch"
    ./sh_pwrite "$MNT/scratch" "a" 1 1
    assert_eq bag "`cat "$MNT/scratch"`"

info "    ...ok"
info "  - overwrite and extend"

    echo "bug" > "$MNT/scratch"
    ./sh_pwrite "$MNT/scratch" "all" 3 1
    assert_eq ball "`cat "$MNT/scratch"`"

info "    ...ok"
info "  - truncate longer"

    echo foo > "$MNT/scratch"
    truncate -s 5 "$MNT/scratch"
    assert_eq 5 "`stat -c "%s" "$MNT/scratch"`"
    assert_eq foo$'\x00'$'\x00' "`cat "$MNT/scratch"`"

info "    ...ok"
info "  - truncate shorter"

    echo foo > "$MNT/scratch"
    truncate -s 2 "$MNT/scratch"
    assert_eq 2 "`stat -c "%s" "$MNT/scratch"`"
    assert_eq "fo" "`cat "$MNT/scratch"`"

info "    ...ok"
info "  - symlink: intrafs"

    echo foo > "$MNT/link_target"
    ln -s "./link_target" "$MNT/intra_link_source"

    assert_eq "foo" "`cat "$MNT/intra_link_source"`"

    echo bar > "$MNT/intra_link_source"
    assert_eq "bar" "`cat "$MNT/link_target"`"

info "    ...ok"
info "  - symlink: interfs"

    echo foo > "/tmp/link_target"
    ln -s "/tmp/link_target" "$MNT/inter_link_source"

    assert_eq "foo" "`cat "$MNT/inter_link_source"`"

    echo bar > "$MNT/inter_link_source"
    assert_eq "bar" "`cat "/tmp/link_target"`"

info "    ...ok"
info "  - rm: mid-directory"

    wd="$MNT/rm-mid-directory"
    mkdir "$wd"
    touch "$wd/f1"
    avail=`stat_avail "$MNT"`

    truncate -s 10000 "$wd/f2"
    assert_eq f1$'\n'f2 "`ls -1 "$wd"`"
    assert_lt `stat_avail "$MNT"` $avail

    assert_ok rm "$wd/f2"
    assert_eq f1 "`ls "$wd"`"
    assert_eq $avail `stat_avail "$MNT"`

info "    ...ok"
info "  - rm: first-in-directory"

    wd="$MNT/rm-first-in-directory"
    mkdir "$wd"
    prev_avail=`stat_avail "$MNT"`

    truncate -s 1MB "$wd/f1"
    touch "$wd/f2"
    assert_eq f1$'\n'f2 "`ls -1 "$wd"`"
    avail=`stat_avail "$MNT"`
    assert_lt $avail $prev_avail

    assert_ok rm "$wd/f1"
    assert_eq f2 "`ls "$wd"`"
    assert_eq `expr $avail + 1003520` `stat_avail "$MNT"` # 1003520 is nearest block multiple of 1MB

info "    ...ok"
info "  - rm: only-in-directory"

    wd="$MNT/rm-only-in-directory"

    avail=`stat_avail "$MNT"`
    mkdir "$wd"
    truncate -s 1MB "$wd/f1"

    assert_eq f1 "`ls "$wd"`"
    assert_lt `stat_avail "$MNT"` $avail

    assert_ok rm "$wd/f1"
    assert_eq "" "`ls "$wd"`"
    assert_eq $avail `stat_avail "$MNT"`

info "    ...ok"
info "  - rmdir: empty"

    mkdir "$MNT/rmdir-empty"
    assert_ok silence stat "$MNT/rmdir-empty"

    assert_ok rmdir "$MNT/rmdir-empty"
    assert_not_ok stat "$MNT/rmdir-empty"

info "    ...ok"
info "  - rmdir: non-empty"

    mkdir "$MNT/rmdir-non-empty"
    assert_ok silence stat "$MNT/rmdir-non-empty"

    touch "$MNT/rmdir-non-empty/foo"
    assert_eq foo "`ls "$MNT/rmdir-non-empty"`"

    assert_not_ok rmdir "$MNT/rmdir-non-empty"
    assert_ok rm -r "$MNT/rmdir-non-empty"
    assert_not_ok stat "$MNT/rmdir-non-empty"

info "    ...ok"
info "  - statfs: available space"

    truncate -s 0 "$MNT/scratch"

    avail=`stat_avail "$MNT"`

    # Should be able to create a file of that size
    assert_ok truncate -s $avail "$MNT/scratch"
    assert_eq $avail "`stat -c "%s" "$MNT/scratch"`"

    # Should be out of space
    assert_eq 0 `stat_avail "$MNT"`
    assert_not_ok truncate -s 1 "$MNT/cannot_create_file"

    truncate -s 0 "$MNT/scratch"
    assert_eq $avail `stat_avail "$MNT"`

info "    ...ok"
info "  - chmod"

    touch "$MNT/scratch"

    new_mode=755
    assert_ne $new_mode "`stat -c "%a" "$MNT/scratch"`"

    assert_ok chmod "$new_mode" "$MNT/scratch"

    assert_eq $new_mode "`stat -c "%a" "$MNT/scratch"`"

info "    ...ok"

info "  - chown"
if $MULTI_USER; then

    touch "$MNT/scratch"

    first_user="`stat -c "%U" "$MNT/scratch"`"
    assert_ne "$OTHER_USER" "$first_user"

    assert_ok sudo chown "$OTHER_USER" "$MNT/scratch"
    assert_eq "$OTHER_USER" "`stat -c "%U" "$MNT/scratch"`"

    assert_ok sudo chown "$first_user" "$MNT/scratch"

info "    ...ok"
else
info "    ...skipped"
fi

info "  - chown: deny non-root"
if $MULTI_USER; then

    touch "$MNT/scratch"

    assert_eq "`stat -c "%U" "$MNT/scratch"`" "`whoami`"
    assert_not_ok chown "$OTHER_USER" "$MNT/scratch"

info "    ...ok"
else
info "    ...skipped"
fi

info "  - chgrp"
if $MULTI_USER; then

    touch "$MNT/scratch"

    first_group="`stat -c "%G" "$MNT/scratch"`"
    assert_ne "$OTHER_USER" "$first_group"

    assert_ok sudo chgrp "$OTHER_USER" "$MNT/scratch"
    assert_eq "$OTHER_USER" "`stat -c "%G" "$MNT/scratch"`"

    assert_ok sudo chgrp "$first_group" "$MNT/scratch"

info "    ...ok"
else
info "    ...skipped"
fi

info "  - chgrp: allow owner"
if $MULTI_USER; then

    touch "$MNT/scratch"

    assert_eq "`stat -c "%U" "$MNT/scratch"`" "`whoami`"

    first_group="`stat -c "%G" "$MNT/scratch"`"
    assert_ne "$OTHER_USER" "$first_group"

    assert_ok chgrp "$OTHER_USER" "$MNT/scratch"
    assert_eq "$OTHER_USER" "`stat -c "%G" "$MNT/scratch"`"

    assert_ok chgrp "$first_group" "$MNT/scratch"

info "    ...ok"
else
info "    ...skipped"
fi

info "  - chgrp: deny other"
if $MULTI_USER; then

    touch "$MNT/scratch"

    assert_eq "`stat -c "%U" "$MNT/scratch"`" "`whoami`"

    first_group="`stat -c "%G" "$MNT/scratch"`"
    assert_ne "$OTHER_USER" "$first_group"

    assert_not_ok sudo -u "$OTHER_USER" chgrp "$OTHER_USER" "$MNT/scratch"

info "    ...ok"
else
info "    ...skipped"
fi

info "Failure injection:"

info "  - mount invalid"

    mkdir /tmp/fakemnt
    truncate -s 10MB /tmp/fakedev
    assert_not_ok ./jfat -d -s -o use_ino /tmp/fakemnt /tmp/fakedev
    fusermount -u /tmp/fakemnt
    rm /tmp/fakedev
    rmdir /tmp/fakemnt

info "    ... ok"
info "  - mkdir and crash"

    mkdir "$MNT/crashdir"
    assert_ok silence stat "$MNT/crashdir"
    st="`stat "$MNT/crashdir"`"

    crash
    start

    assert_eq "$st" "`stat "$MNT/crashdir"`"

info "    ...ok"
info "  - truncate and crash"

    truncate -s 42 "$MNT/crashfile"
    assert_ok silence stat "$MNT/crashfile"
    st="`stat "$MNT/crashfile"`"

    crash
    start

    assert_eq "$st" "`stat "$MNT/crashfile"`"

info "    ...ok"
info "  - write and crash"

    echo "foo" > "$MNT/crashfile"
    assert_eq "foo" "`cat "$MNT/crashfile"`"

    crash
    start

    assert_eq "foo" "`cat "$MNT/crashfile"`"

info "    ...ok"
info "  - rm and crash"

    truncate -s 0 "$MNT/crashfile"
    avail=`stat_avail "$MNT"`

    assert_ok truncate -s $avail "$MNT/crashfile"
    assert_not_ok truncate -s 1 "$MNT/no-space-for-file"

    assert_ok rm "$MNT/crashfile"
    crash
    start

    assert_eq $avail `stat_avail "$MNT"`
    assert_ok truncate -s 1 "$MNT/space-for-file"

info "    ...ok"
info "  - rmdir and crash"

    mkdir -p "$MNT/crashdir"
    assert_ok ls "$MNT/crashdir"

    assert_ok rmdir "$MNT/crashdir"
    crash
    start

    assert_not_ok ls "$MNT/crashdir"

info "    ...ok"

info "All good!"
stop
