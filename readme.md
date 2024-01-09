## Wireshark Dissectors for CSP

These dissectors are designed for CubeSat Space Protocol (CSP) and are
compatible with both CSPv1 and CSPv2 on CAN frames. To use them, copy
the dissectors into your [Wireshark plugin directory][1] and run
Wireshark. Since it's not possible to determine the CSP version from
the data alone, you need to manually select the desired
dissector. This can be done by placing the corresponding dissector in
your plugin directory or enabling/disabling it via Menu -> Analyze ->
Enabled Protocols...

Due to CSP utilizing CAN ID as part of its structure, it cannot
function as a subdissector, meaning you can't use it with "Decode
As...". It is registered as a post dissector.

### Requirements

- libpcap v1.10.2 or later
- Socketcan (Note: Windows does not support Socketcan)
- Wireshark

### Notes for WSL Users

The current stable version of Windows Subsystem for Linux (WSL) uses
libpcap v1.10.1, which [does not utilize `DLT_CAN_SOCKETCAN` for
CANbus][2]. Ensure that you install the latest libpcap version
manually.

[1]: https://www.wireshark.org/docs/wsug_html_chunked/ChPluginFolders.html
[2]: https://github.com/the-tcpdump-group/libpcap/issues/1052
