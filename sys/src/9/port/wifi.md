# 802.11n implementation status

## implemented
- core: parse ht capabilities (ie 45) and ht operation (ie 61) from beacons
- core: advertise ht capabilities ie in probe and assoc requests
- core: mcs rate adaptation (up/down every 256 tx)
- core: speed lookup tables for 1/2 stream, 20/40mhz, gi/sgi
- iwl: init ht capabilities for family >= 7000 (7260, 8260, 9260)
- iwl: ht negotiation in rxon (intersection of driver and ap)
- iwl: dynamic phy context for 20/40mhz channel width
- iwl: station flags ht20/ht40 for firmware
- iwl: tx rate with mcs index, 0x20 ht marker, 0x10 40mhz, 0x08 sgi
- iwl: mimo (both antennas) for ht
- iwl: link speed from mcs lookup
- iwl: wifistat shows ht mcs and channel width

## not implemented (by choice)
- a-msdu aggregation (ethernet frame coalescing before cipher)
- a-mpdu aggregation (mpdu coalescing after cipher, requires addba)
- block ack (addba negotiation)
- txop burst (no gain without a-mpdu)
- ht for family < 7000 (4965, 5000, 5300, 6000)
- 802.11ac (vht)

## priority (if extending)

### short term (medium gain, low effort)
1. A-MSDU aggregation (~100 lines, wifi.c only, no firmware changes)
   coalesce ethernet frames up to 7935 bytes before cipher.
   +5-10% real tcp throughput. small improvement, small code.

### medium term (high gain, high effort)
2. A-MPDU aggregation + ADDBA (~2 weekends, wifi.c + etheriwl.c)
   hardware can burst 64KB of mpdus with single block ack.
   +200-300% real tcp throughput. the big jump.

### long term (low priority)
3. TXOP bursting (~10 lines, etheriwl.c only)
   depends on A-MPDU. no gain without it.
4. HT for family < 7000 (~50 lines, needs hardware to test)
5. 802.11ac (driver does not support it at all)

### optimal stack order

```
eth[1] eth[2] eth[3]
    |
    v
  a-msdu       <- coalesce ethernet frames (wifi.c)
    |
    v
  cipher        <- ccmp on aggregated frame (one mic)
    |
    v
  a-mpdu        <- coalesce encrypted mpdus (firmware handles this)
    |
    v
  txop          <- hold channel for multiple ppdus (hardware param)
    |
    v
  radio
```
