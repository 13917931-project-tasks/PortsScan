spicy_add_analyzer(
    NAME portsscan
    PACKAGE_NAME PortsScan
    SOURCES portsscan.spicy portsscan.evt zeek_portsscan.spicy
    SCRIPTS __load__.zeek main.zeek dpd.sig
)
