# Hard - Hardened Buffers for Rust
[![crates.io](https://img.shields.io/crates/v/hard.svg)](https://crates.io/crates/hard)
[![docs.rs](https://docs.rs/hard/badge.svg)](https://docs.rs/hard)

Storing sensitive data (cryptographic keys, passwords, plaintexts, etc.) can be
fraught with issues. Data can be recovered from uninitialised memory, from the
contents of core dumps/crash reports, or accidentally revealed via buffer
overflows.

Hard attempts to provide buffer types which are hardened against these types of
errors. Based on the [libsodium](https://doc.libsodium.org/) cryptographic
library, we make use of its [secure memory
utilities](https://doc.libsodium.org/memory_management#guarded-heap-allocations)
to allocate and manage the memory backing buffer types. Memory allocated using
hard is placed directly at the end of a page, followed by a guard page, so any
buffer overflow will immediately result in the termination of the program. A
canary is placed before the allocated memory to detect modifications on free,
and another guard page is placed before this. Finally, operating system is
advised not to swap the memory to disk, or include it in crash reports/core
dumps.

For more information, see the [docs](https://docs.rs/hard).

## Security/Vulnerability Disclosures
If you find a vulnerability in hard, please immediately contact `tom25519@pm.me`
with details.

My [age](https://github.com/FiloSottile/age) public key (preferred) is:

```text
age1gglesedq4m2z9kc7urjhq3zlpc6qewcwpcna7s0lwh8k2c4e6fxqf3kdvq
```

My PGP public key has fingerprint `0x4712EC7C9F404B14`, and is available from
[keyserver.ubuntu.com](https://keyserver.ubuntu.com),
[pgp.mit.edu](https://pgp.mit.edu/), or
[Github](https://github.com/tom25519.gpg).

## License
Licensed under either of:

 * Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or
   http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license ([LICENSE-MIT](LICENSE-MIT) or
   http://opensource.org/licenses/MIT)

at your option.

## Contribution
Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.
