# zeek-iec104
A Zeek Parser for the IEC 60870-5-104 protocol (aka IEC 104) built using Spicy. 

## Overview

Zeek-iec104 is a Zeek plugin (written in [Spicy](https://docs.zeek.org/projects/spicy/en/latest/)) for parsing and logging fields used by the IEC 104 protocol. This protocol transmitts supervisory data and data acquisition requests for controlling
power transmission grids. As many other industrial protocols, it was first used over serial connections as IEC 60870-5-101, but today its messages are as application data (L7) over TCP port 2404. The communication follows a standard client-server model or what is referred to the IEC terminonoly as *controlled and the controlling stations*.

The parsing logic of this plugin was developed based on the corresponding Wireshark disssector and the technlology report produces by Brno University of Technology (see *Resources*).

This parser produces one log file, `iec104.log`, defined under [scripts/main.zeek](./scripts/main.zeek).

The *Logging Capabilities* section below provides more details for the current fields that are supported.

## Installation

TODO: Neede to add some installation instructions once sure that most of the features are tested and work.

## Logging Capabilities

### IEC 104 Log (iec104.log)

#### Fields Captured
This log captures and logs each IEC 104 message transmitted over TCP port 2404 to `iec104.log`. All packets related to IEC 104 are captured in that single file for now.

TODO: Have a simple table with all the fields that we currently support.

## Resources

Various resources that assist to the development of this parser.

* Wireshark IEC 104 Dissector: https://github.com/wireshark/wireshark/blob/28c3b0dffad10843c50d74ea595fdd2ac41fa068/epan/dissectors/packet-iec104.c

* Matoušek, Petr. "Description and analysis of IEC 104 Protocol." Faculty of Information Technology, Brno University o Technology, Tech. Rep (2017).

## PCAPs

* The trace under [first](./testing/Traces/first/) has been acquired form: https://github.com/automayt/ICS-pcap/blob/master/IEC%2060870/iec104/iec104.pcap

* The traces under the [second](./testing/Traces/second/) directory come from the "20200608_UOWM_IEC104_Dataset_mitm_drop" in: https://zenodo.org/record/7108614#.ZFR6oJHML0o

## Streams

The streams for the above PCAPs are created using ``zeek -C -r <path to PCAP> Conn::default_extract=T``. For the files in the **second/** directory the ``-C`` option needs to be provided to properly extract the IEC 104 streams.
