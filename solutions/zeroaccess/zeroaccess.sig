signature zeroaccess {
    ip-proto == udp
    payload /....\x28\x94\x8d\xab.*/
    event "zeroacess"
}
