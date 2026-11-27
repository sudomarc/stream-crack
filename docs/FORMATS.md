# Capture Formats

## PCAP
Validate magic value, byte order, version, snap length, link type, packet-header lengths, timestamp fields, and truncation.

## PCAPNG
Initial support should cover Section Header Block, Interface Description Block, and Enhanced Packet Block. Validate byte-order magic, block length/alignment, interface references, captured length, and original length.

## Link types
Decode only link types with tested decoders. Unknown types may be retained as opaque records but must never be misinterpreted as 802.11.

## Resource limits
Check limits before allocation. Bound file size, block size, packet size, record count, and retained metadata. Prefer streaming over loading entire captures.

## Fixtures
Commit only synthetic or explicitly redistributable files. Never commit private user captures.
