spicy_add_analyzer(
    NAME iec104
    PACKAGE_NAME spicy-iec104
    SOURCES iec104.spicy iec104.evt zeek_iec104.spicy
    SCRIPTS __load__.zeek main.zeek dpd.sig
)
