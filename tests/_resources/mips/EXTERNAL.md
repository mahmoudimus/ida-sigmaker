# Optional MIPS Executable Acceptance Fixtures

The integration test can also exercise the MIPS relocatable-immediate rule
against a real MIPS executable in both byte orders. These assets are not
vendored: the catalog repository does not publish a license for them.

The test expects the following files in `SIGMAKER_MIPS_ACCEPTANCE_DIR`:

| File | IDA byte order | Git blob | SHA-256 |
| --- | --- | --- | --- |
| `netcat-mipsel32-dynamic-debian-squeeze` | little-endian | `b3e049f224d012fbe4a5c8846bbad3cd93497be8` | `fb4ea8537d13e8a4bbbbcdcc2e4ba78133b743e9d7f5938c7885c9729bc39932` |
| `netcat-mips32-dynamic-debian-squeeze` | big-endian | `5674b10cbaf7b4bc2485df6dde50ca188b41eb4e` | `1e36c15e957a2ef2858a5792329ea6bdd4be601f32bdfceb97ce38f987db8793` |

They were cataloged at `hypn/misc-binaries` commit
`3758eabc5d2b65648b5962ddc945aab56c2db2af`.

```bash
fixtures=/tmp/sigmaker-mips-acceptance
mkdir -p "$fixtures"
curl --fail --location \
  https://raw.githubusercontent.com/hypn/misc-binaries/3758eabc5d2b65648b5962ddc945aab56c2db2af/netcat-mipsel32-dynamic-debian-squeeze \
  -o "$fixtures/netcat-mipsel32-dynamic-debian-squeeze"
curl --fail --location \
  https://raw.githubusercontent.com/hypn/misc-binaries/3758eabc5d2b65648b5962ddc945aab56c2db2af/netcat-mips32-dynamic-debian-squeeze \
  -o "$fixtures/netcat-mips32-dynamic-debian-squeeze"
shasum -a 256 "$fixtures"/*
SIGMAKER_MIPS_ACCEPTANCE_DIR="$fixtures" \
  python -m unittest tests.integration_test_sigmaker.TestMipsExternalExecutableAcceptance -v
```

The test verifies that IDA opens both executables as MIPS, reports the expected
endianness, and leaves every non-relocated instruction byte exact.
