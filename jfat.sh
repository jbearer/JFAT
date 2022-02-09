MNT=mnt
DEV=dev
LOG="$0.log"

JFAT_EXE=./jfat

OTHER_USER="test"

if cut -d ':' -f 1 /etc/passwd | grep "$OTHER_USER"; then
    MULTI_USER=true
else
    MULTI_USER=false
fi

JFAT_PID=0
function start()
{
    if $MULTI_USER; then
        allow_other="-o allow_other"
    else
        allow_other=""
    fi
    
    if [[ "$JFAT_DEBUG" == "1" ]]; then
        debug="-d"
    else
        debug="-f"
    fi
    echo "$debug"

    $JFAT_EXE $debug -s -o use_ino $allow_other "$MNT" "$DEV" >> "$LOG" 2>&1 &
    JFAT_PID=$!
    echo "Started $JFAT_PID"
    sleep 1

    if [[ "`mount | tail -n 1 | cut -d ' ' -f 1`" != "`pwd -P`/jfat" ]]; then
        echo "JFAT mount failed!"
        exit 1
    fi
    if ! ps | grep $JFAT_PID; then
        echo "JFAT mount failed!"
        exit 1
    fi
}

function crash()
{
    if [[ $JFAT_PID == 0 ]]; then
        error "JFAT is not running!"
        exit 1
    else
        kill -9 $JFAT_PID
        fusermount -u "$MNT"
    fi
}

function stop()
{
    fusermount -u "$MNT"
}

if [[ $# == 1 ]] && [[ "$1" == "--valgrind" ]]; then
    JFAT_EXE="valgrind ./jfat"
fi

truncate -s 0 "$LOG"
rm -f "$DEV"
