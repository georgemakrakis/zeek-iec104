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
This log captures and logs each IEC 104 message transmitted over TCP port 2404 to `iec104.log`. All packets up to the ASDU's Common Address are logged in a single file. After that, based on the ASDU type, a list is populated and a corresponding log file is created. The list contains indices with the correponding IOAs that might exist. This way a multitude of them in a single packete they can be logged together. The structure of the main `iec104.log` file follows:


| Field             | Type           | Description                                               |
| ----------------- |----------------|-----------------------------------------------------------| 
| ts                | time           | Timestamp                                                 |
| uid               | string         | Unique ID for this connection                             |
| id                | conn_id        | Default Zeek connection info (IP addresses, ports)        |
| apdu_len          | count          | Length of the IEC part                                    |
| apci_type         | count          | The APCI frame type                                       |
| apci_tx           | count          | APCI trasmit counter                                      |
| apci_rx           | count          | APCI receive counter                                      |
| info_obj_type     | ASDU Info Obj Type          | Type identification (TypeID)                 |
| seq               | count          | Structure qualifier                                       |
| num_ix            | count          | Number of objects/elements                                |
| cause_tx          | count          | Cause of transmission (COT)                               |
| negative          | count          | P/N positive or negative confirmation of an activation    |
| test              | count          | Test bit, generated during test conditions                |
| originator_address | count         | Originator Address                                        |
| common_address    | count          | ASDU Address Field (Common Address of ASDU, COA)          |


Below is also a list of the currently implemented information object codes.

| Reference         | TypeID           | Implemented                |
| ----------------- |------------------|----------------------------|
|M_SP_NA_1          |1|x
|M_SP_TA_1          |2|x
|M_DP_NA_1          |3| 
|M_DP_TA_1          |4|x
|M_ST_NA_1          |5|x
|M_ST_TA_1          |6|x
|M_BO_NA_1          |7|  
|M_BO_TA_1          |8|x
|M_ME_NA_1          |9|x
|M_ME_TA_1          |10|x
|M_ME_NB_1          |11|x
|M_ME_TB_1          |12|x
|M_ME_NC_1          |13|
|M_ME_TC_1          |14|x
|M_IT_NA_1          |15|
|M_IT_TA_1          |16|
|M_EP_TA_1          |17|
|M_EP_TB_1          |18|
|M_EP_TC_1          |19| 
|M_PS_NA_1          |20| 
|M_ME_ND_1          |21|
|# The 22-29 do not exist or are reserved?
|M_SP_TB_1          |30|x
|M_DP_TB_1          |31|
|M_ST_TB_1          |32|x
|M_BO_TB_1          |33|x
|M_ME_TD_1          |34|x
|M_ME_TE_1          |35|x
|M_ME_TF_1          |36|x
|M_IT_TB_1          |37|
|M_EP_TD_1          |38|
|M_EP_TE_1          |39|
|M_EP_TF_1          |40|
|# The 41-44 do not exist or are reserved?
|C_SC_NA_1          |45|x
|C_DC_NA_1          |46|x
|C_RC_NA_1          |47|x
|C_SE_NA_1          |48|
|C_SE_NB_1          |49|x
|C_SE_NC_1          |50|
|C_BO_NA_1          |51|x
|# 52-57 do not exist or are reserved?
|C_SC_TA_1          |58|
|C_DC_TA_1          |59|
|C_RC_TA_1          |60|
|C_SE_TA_1          |61|
|C_SE_TB_1          |62|
|C_SE_TC_1          |63|
|C_BO_TA_1          |64|
|#65-69 do not exist or are reserved?
|M_EI_NA_1          |70|x
|#The 71-99 do not exist or are reserved?
|C_IC_NA_1          |100|Y
|C_CI_NA_1          |101|
|C_RD_NA_1          |102|x
|C_CS_NA_1          |103|
|C_TS_NA_1          |104|
|C_RP_NC_1          |105|x
|C_CD_NA_1          |106|
|C_TS_TA_1          |107|
|# The 108-109 do not exist or are reserved? 
|P_ME_NA_1          |110|
|P_ME_NB_1          |111|
|P_ME_NC_1          |112|
|P_AC_NA_1          |113|
|# 114-119 do not exist or are reserved?
|F_FR_NA_1          |120|
|F_SR_NA_1          |121| 
|F_SC_NA_1          |122|
|F_LS_NA_1          |123|
|F_AF_NA_1          |124|
|F_SG_NA_1          |125|
|F_DR_TA_1          |126|
|F_SC_NB_1          |127|
## Resources

Various resources that assist to the development of this parser.

* Wireshark IEC 104 Dissector: https://github.com/wireshark/wireshark/blob/28c3b0dffad10843c50d74ea595fdd2ac41fa068/epan/dissectors/packet-iec104.c

* Matoušek, Petr. "Description and analysis of IEC 104 Protocol." Faculty of Information Technology, Brno University o Technology, Tech. Rep (2017).

## PCAPs

* The trace under [first](./testing/Traces/first/) has been acquired form: https://github.com/automayt/ICS-pcap/blob/master/IEC%2060870/iec104/iec104.pcap

* The traces under the [second](./testing/Traces/second/), [third](./testing/Traces/third/) and [fourth](./testing/Traces/fourth/) directories come from the "20200608_UOWM_IEC104_Dataset_mitm_drop" in: Panagiotis, Konstantinos, Thomas, Vasileios, & Panagiotis. (2022). IEC 60870-5-104 Intrusion Detection Dataset [Data set]. https://doi.org/10.21227/fj7s-f281 and https://zenodo.org/record/7108614#.ZFR6oJHML0o 

## Streams

The streams for the above PCAPs are created using ``zeek -C -r <path to PCAP> Conn::default_extract=T``. For the files in the **second/**,  **third/** and  **fourth/** directories the ``-C`` option needs to be provided to properly extract the IEC 104 streams. The same applied for testing the parser in Zeek.
