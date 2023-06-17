# @TEST-DOC: Test Zeek parsing a trace file through the iec104 analyzer.
#
# @TEST-EXEC: zeek -Cr ${TRACES}/tcp-port-12345.pcap ${PACKAGE} %INPUT >output
# @TEST-EXEC: btest-diff output
# @TEST-EXEC: btest-diff iec104.log

# TODO: Adapt as suitable. The example only checks the output of the event
# handlers.

event iec104::message(c: connection, is_orig: bool, payload: string)
    {
    print fmt("Testing iec104: [%s] %s %s", (is_orig ? "request" : "reply"), c$id, payload);
    }
