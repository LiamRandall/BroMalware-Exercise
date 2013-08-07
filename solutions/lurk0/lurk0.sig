signature lurk0 {
    ip-proto == tcp
    # LURK0
    payload /\x4c\x55\x52\x4b\x30.*/
    event "lurk0"
}
