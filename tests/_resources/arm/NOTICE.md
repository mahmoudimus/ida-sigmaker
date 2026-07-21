# ARM Thumb Fixture Notice

`hal_cm.o` is an unchanged third-party test fixture. It is the `hal_cm.o`
archive member extracted from `RTX_CM0.lib` in the Arm CMSIS-RTOS RTX package.
It is used only to make IDA's combined Thumb `MOVS`/`LSLS` decoding reproducible
in the integration suite.

Source material, pinned for provenance:

- Repository: `https://github.com/labapart/polymcu`
- Commit: `565019e30e80e5736ca1034e93241076c2a80672`
- Archive: `RTOS/RTX/LIB/ARM/RTX_CM0.lib`
- Archive SHA-256: `7c21510d107fe8ecec908935328620ac463a3eb2dcd8d4b7b799c6c5b650f12a`
- Member: `hal_cm.o`
- Fixture SHA-256: `826fb4f623463edd2bd97cb17063cd7cc3570b7803d3d2e4542fca06731797e6`
- Corresponding source notice:
  `RTOS/RTX/SRC/HAL_CM.c`

The source header supplies the following BSD-3-Clause license notice:

```text
Copyright (c) 1999-2009 KEIL, 2009-2015 ARM Germany GmbH
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:
  - Redistributions of source code must retain the above copyright
    notice, this list of conditions and the following disclaimer.
  - Redistributions in binary form must reproduce the above copyright
    notice, this list of conditions and the following disclaimer in the
    documentation and/or other materials provided with the distribution.
  - Neither the name of ARM nor the names of its contributors may be used
    to endorse or promote products derived from this software without
    specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
ARE DISCLAIMED. IN NO EVENT SHALL COPYRIGHT HOLDERS AND CONTRIBUTORS BE
LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
POSSIBILITY OF SUCH DAMAGE.
```
