# 0.4.0 (December 2021)
Generation of `BufferReadOnly` and `BufferNoAccess` types (plus all associated traits and methods)
is now not done by default - the `restricted-types` feature must be enabled to generate this code.
For a lot of users, these types will just be noise that they'd prefer not to introduce into their
API, so making them opt-in makes more sense IMO.

# 0.3.1 (December 2021)
No major changes, version bump + doc tweaks only.

# 0.3.0 (December 2021)
Removed the `fill_random` API. Thinking further about this, this doesn't seem like something that
this crate needs to do. Keep the crate minimal.

# 0.2.2 (November 2021)
Switch from using `libsodium-sys` to `libsodium-sys-stable` for bindings to Sodium: `libsodium-sys`
is part of Sodiumoxide, which is now deprecated. `libsodium-sys-stable` is maintained by jedisct1,
the author of Sodium.

# 0.2.1 (June 2021)
Added the `fill_random` API, which fills a buffer with cryptographically secure pseudo-random data,
generated using the Sodium `randombytes` API.

# 0.2.0 (June 2021)
Updated the `buffer_type` macro such that multiple buffer types can be defined in a single macro
invocation.

# 0.1.1 (June 2021)
Bugfix: Re-exported the `paste` crate to ensure the crate works when imported elsewhere.

# 0.1.0 (June 2021)
Initial release.
