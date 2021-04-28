# Netprofiler-CEF-format
Netprofiler Arcsght Integration

Script that converts SteelCentral Netprofiler Syslog messages in to CEF format.

Currently tested with User-Defined, Security and ASM events.

```pip3 install cefevent```

Change ```sock.sendto(byte_message, ('localhost', 8888))``` to relay cef messages to arcsight logger.

to run script: ```python3 pysyslog.py```

output :
```
[admin@tamriell ~]# python3 Desktop/pysyslog.py
       Writing to: pysyslog.log
     Listening on: 8080
         Bound to: 0.0.0.0
Ignored Arguments: []

Starting Server, press Ctrl+C to shutdown.

CEF:0|RiverbedTechnology,Inc.|netrofiler-ve|10.19|ftnbi_ddos_flood@41180|ASM DDoS|1|cs1=1.67 cs1Label=PEAK_BYTES_IN cs2=0.03 cs2Label=PEAK_PACKETS_IN cs3=1.67 cs3Label=PEAK_BYTES_OUT cs4Label=PEAK_PACKETS_OUT shost=8.8.8.0/24 52.20.0.0/14 
8.8.4.0/24 52.14.0.0/16 35.156.0.0/14 start=1619601230.262701 end=1619601230.262701 sourceTranslatedPort=54248 dst=10.65.170.2 msg=﻿An alert of type ASM DDoS has been triggered by policy Volumetric DDoS - lab. Details: Detected target 10.6
5.170.2 port 54248 protocol 6 peak_packets_psec 0.03 peak_bytes_psec 1.67 source_block_count 0 sources 8.8.8.0/24 52.20.0.0/14 8.8.4.0/24 52.14.0.0/16 35.156.0.0/14                                                                           
CEF:0|RiverbedTechnology,Inc.|netrofiler-ve|10.19|ftnbi_threshold_exceeded@41180|ASM Threshold|1|cs1=1.90 cs1Label=PEAK_BYTES_IN cs2Label=PEAK_PACKETS_IN cs3=1.90 cs3Label=PEAK_BYTES_OUT cs4Label=PEAK_PACKETS_OUT start=1619601230.262511 en
d=1619601230.262511 sourceTranslatedPort=47491 msg=﻿An alert of type ASM Threshold has been triggered by policy Bit Rate for UDP/47491 Into lab. Details: Threshold 1 (bytes_in) exceeded. Peak: 1.90                                          
CEF:0|RiverbedTechnology,Inc.|netrofiler-ve|10.19|ftnbi_threshold_exceeded@41180|ASM Threshold|1|cs1=2.95 cs1Label=PEAK_BYTES_IN cs2Label=PEAK_PACKETS_IN cs3=2.95 cs3Label=PEAK_BYTES_OUT cs4Label=PEAK_PACKETS_OUT start=1619601230.262563 en
d=1619601230.262563 sourceTranslatedPort=48088 msg=﻿An alert of type ASM Threshold has been triggered by policy Bit Rate for UDP/48088 Into lab. Details: Threshold 1 (bytes_in) exceeded. Peak: 2.95                                          
CEF:0|RiverbedTechnology,Inc.|netrofiler-ve|10.19|ftnbi_threshold_exceeded@41180|ASM Threshold|1|cs1=1.67 cs1Label=PEAK_BYTES_IN cs2Label=PEAK_PACKETS_IN cs3=1.67 cs3Label=PEAK_BYTES_OUT cs4Label=PEAK_PACKETS_OUT start=1619601230.262631 en
d=1619601230.262631 sourceTranslatedPort=54248 msg=﻿An alert of type ASM Threshold has been triggered by policy Bit Rate for TCP/54248 Into lab. Details: Threshold 1 (bytes_in) exceeded. Peak: 1.67                                          
CEF:0|RiverbedTechnology,Inc.|netrofiler-ve|10.19|ftnbi_threshold_exceeded@41180|ASM Threshold|1|cs1=1.90 cs1Label=PEAK_BYTES_IN cs2Label=PEAK_PACKETS_IN cs3=1.90 cs3Label=PEAK_BYTES_OUT cs4Label=PEAK_PACKETS_OUT start=1619601230.262589 en
d=1619601230.262589 sourceTranslatedPort=27291 msg=﻿An alert of type ASM Threshold has been triggered by policy Bit Rate for UDP/27291 Into lab. Details: Threshold 1 (bytes_in) exceeded. Peak: 1.90                                          
CEF:0|RiverbedTechnology,Inc.|netrofiler-ve|10.19|ftnbi_threshold_exceeded@41180|ASM Threshold|1|cs1=1.67 cs1Label=PEAK_BYTES_IN cs2Label=PEAK_PACKETS_IN cs3=1.67 cs3Label=PEAK_BYTES_OUT cs4Label=PEAK_PACKETS_OUT start=1619601230.262609 en
d=1619601230.262609 sourceTranslatedPort=42096 msg=﻿An alert of type ASM Threshold has been triggered by policy Bit Rate for TCP/42096 Into lab. Details: Threshold 1 (bytes_in) exceeded. Peak: 1.67                                          
CEF:0|RiverbedTechnology,Inc.|netrofiler-ve|10.19|ftnbi_ddos_flood@41180|ASM DDoS|1|cs1=1.67 cs1Label=PEAK_BYTES_IN cs2=0.03 cs2Label=PEAK_PACKETS_IN cs3=1.67 cs3Label=PEAK_BYTES_OUT cs4Label=PEAK_PACKETS_OUT shost=8.8.8.0/24 52.20.0.0/14 
8.8.4.0/24 52.14.0.0/16 35.156.0.0/14 start=1619601230.262673 end=1619601230.262673 sourceTranslatedPort=42096 dst=10.65.170.2 msg=﻿An alert of type ASM DDoS has been triggered by policy Volumetric DDoS - lab. Details: Detected target 10.6
5.170.2 port 42096 protocol 6 peak_packets_psec 0.03 peak_bytes_psec 1.67 source_block_count 0 sources 8.8.8.0/24 52.20.0.0/14 8.8.4.0/24 52.14.0.0/16 35.156.0.0/14                                                                           
CEF:0|RiverbedTechnology,Inc.|netrofiler-ve|10.19|ftnbi_ddos_flood@41180|ASM DDoS|1|cs1=3.77 cs1Label=PEAK_BYTES_IN cs2=0.03 cs2Label=PEAK_PACKETS_IN cs3=3.77 cs3Label=PEAK_BYTES_OUT cs4Label=PEAK_PACKETS_OUT shost=8.8.8.0/24 52.20.0.0/14 
8.8.4.0/24 52.14.0.0/16 35.156.0.0/14 start=1619601240.274222 end=1619601240.274222 sourceTranslatedPort=48590 dst=10.65.170.2 msg=﻿An alert of type ASM DDoS has been triggered by policy Volumetric DDoS - lab. Details: Detected target 10.6
5.170.2 port 48590 protocol 17 peak_packets_psec 0.03 peak_bytes_psec 3.77 source_block_count 0 sources 8.8.8.0/24 52.20.0.0/14 8.8.4.0/24 52.14.0.0/16 35.156.0.0/14                                                                          
CEF:0|RiverbedTechnology,Inc.|netrofiler-ve|10.19|ftnbi_threshold_exceeded@41180|ASM Threshold|1|cs1=3.77 cs1Label=PEAK_BYTES_IN cs2Label=PEAK_PACKETS_IN cs3=3.77 cs3Label=PEAK_BYTES_OUT cs4Label=PEAK_PACKETS_OUT start=1619601240.274152 en
d=1619601240.274152 sourceTranslatedPort=48590 msg=﻿An alert of type ASM Threshold has been triggered by policy Bit Rate for UDP/48590 Into lab. Details: Threshold 1 (bytes_in) exceeded. Peak: 3.77                                          
CEF:0|RiverbedTechnology,Inc.|netrofiler-ve|10.19|ftnbi_ddos_flood@41180|ASM DDoS|1|cs1=7.47 cs1Label=PEAK_BYTES_IN cs2=0.12 cs2Label=PEAK_PACKETS_IN cs3=7.47 cs3Label=PEAK_BYTES_OUT cs4Label=PEAK_PACKETS_OUT shost=8.8.8.0/24 52.20.0.0/14 
8.8.4.0/24 52.14.0.0/16 35.156.0.0/14 start=1619601240.274268 end=1619601240.274268 dst=10.65.170.2 msg=﻿An alert of type ASM DDoS has been triggered by policy Volumetric DDoS - lab. Details: Detected target 10.65.170.2 port 0 protocol 1 p
eak_packets_psec 0.12 peak_bytes_psec 7.47 source_block_count 0 sources 8.8.8.0/24 52.20.0.0/14 8.8.4.0/24 52.14.0.0/16 35.156.0.0/14                                                                                                          
CEF:0|RiverbedTechnology,Inc.|netprofiler-ve|10.19|EventManagerID@17163|ASM DDoS|3|request=https://10.65.170.112/event_viewer.php?id\=59306 start=1619601070 src=10.65.170.112 spt=8080 proto=tcp                                              
10.19 RiverbedTechnology,Inc. netprofiler-ve                                                                                                                                                                                                   
CEF:0|RiverbedTechnology,Inc.|netprofiler-ve|10.19|EventManagerID@17163|ASM Exfiltration|1|request=https://10.65.170.112/event_viewer.php?id\=59307 start=1619601143 src=10.65.170.112 spt=8080 proto=udp                                      
10.19 RiverbedTechnology,Inc. netprofiler-ve                    

```

