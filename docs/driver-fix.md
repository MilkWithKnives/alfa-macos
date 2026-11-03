# RTL8821A PHY table initialization on macOS

## Pins and scope

- Kismet: `49b2884770c515186762bba5166fcb53fabae7fa`
- wifit3: `a106dffc62824d1e63658d4b82c709893939521d` (0.7.0)
- Adapter: ALFA AWUS036ACS, USB `0bda:0811`, RTL8811AU
- Host: Apple M4, macOS 27.2 arm64
- Firmware observed during testing: RTL8821A 42.4.0, supplied by Kismet

The capture fix applies to Kismet's userspace `rtw8821a` path. Injection is a separate wifit3 path, not a new TX API added to Kismet.

## Failure

`capture_userspace_usb_wifi/kcompat/include/kcompat/bits.h` did not define the Linux compatibility macros `__LITTLE_ENDIAN` and `__LITTLE_ENDIAN_BITFIELD` on this macOS build. The compatibility base header already rejects unsupported big-endian builds.

In `capture_userspace_usb_wifi/drivers/rtw88/main.h`, `struct rtw_phy_cond` chooses its bitfield layout using `#ifdef __LITTLE_ENDIAN`. Without that macro the wrong layout was selected. Table branch markers such as `0x8000020c` and `0x40000000` became register addresses, narrowed by USB register access to `0x020c` and `0x0000`.

The write to system control corrupted initialization. Instrumentation observed SYS changing from `dc1f` to `501c`, MAC reads returning `EAEAEAEA`, repeated H2C failures, and no received frames. This particular failure was a software byte-order issue; an unlit LED alone does not diagnose USB power.

## Change and evidence

[kismet-little-endian.patch](../patches/kismet-little-endian.patch) defines the missing compatibility macros. It does not modify firmware, skip failed initialization, or increase timeouts.

`tests/byteorder.c` replaces table register-write callbacks with a recorder. It tests both paths of a synthetic IF/ELSE table and then traverses the actual RTL8821A AGC table without opening hardware.

| Check | Before | After |
| --- | --- | --- |
| AGC table callbacks | 252 | 130 |
| Invalid AGC register addresses | 6 | 0 |
| Synthetic conditional branches | Incorrect | Both pass |

Hardware follow-up with the patched helper observed 950 frames in 15 seconds, including 149 bad-FCS frames, and zero H2C errors. A subsequent Kismet session logged 4,376 packets, 54 devices, and 18 SSIDs. These are observations from one setup, not throughput or compatibility guarantees.

The independent wifit3 probe test submitted five directed requests and received 14 matching response frames on channel 1. Received frames were checked for probe-response subtype, target SSID/BSSID, AP source address, and the fresh test destination MAC.

## Reproducing the regression

`alfa-setup` applies the patch and runs the C test before installing the resulting helper. Set a fresh `ALFA_DRIVER_DIR` to keep an existing working build untouched:

```sh
ALFA_DRIVER_DIR="$HOME/.local/opt/kismet-alfa-test" alfa-setup
```

Build logs and the pinned source checkout remain in that directory. The regression test proves table parsing; receive/transmit functionality still requires the adapter and a hardware test.
