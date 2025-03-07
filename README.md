# HK Telemetory Decoder

## How to use
Setup [rust with cargo](https://doc.rust-lang.org/cargo/getting-started/installation.html)


```
make
./c_decoder $(BINARY_PATH)
./rs_decoder $(BINARY_PATH)
```

## Environment
Linux 6.13.5-arch1-1 x86_64 GNU/Linux

gcc (GCC) 14.2.1 20250207

GNU C Library (GNU libc) stable release version 2.41.

rustc 1.85.0 (4d91de4e4 2025-02-17)

## Links

https://github.com/nasa/cFS/discussions/720

https://github.com/nasa/DS/blob/f04f6a04da60a3a003200cccb99ff71008f97f1e/fsw/inc/ds_msg.h

https://github.com/nasa/cFE/blob/ee187426d08e0d4f0edf640d07381b8f676be8d3/modules/msg/fsw/inc/ccsds_hdr.h

https://github.com/nasa/cFE/blob/ee187426d08e0d4f0edf640d07381b8f676be8d3/modules/msg/option_inc/default_cfe_msg_hdr_pri.h

https://github.com/nasa/cFE/blob/ee187426d08e0d4f0edf640d07381b8f676be8d3/modules/msg/option_inc/default_cfe_msg_sechdr.h
