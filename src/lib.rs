//! Security-hardened buffers for storing sensitive data in memory.
//!
//! This crate provides hardened buffer types backed by memory allocated using
//! [libsodium](https://libsodium.org)'s [secure memory management
//! utilities](https://doc.libsodium.org/memory_management#guarded-heap-allocations). The intention
//! is to provide types for securely storing sensitive data (cryptographic keys, passwords, etc).
//!
//! Memory allocated using hard is placed directly at the end of a page, followed by a guard page,
//! so any buffer overflow will immediately result in the termination of the program. A canary is
//! placed before the allocated memory to detect modifications on free, and another guard page is
//! placed before this. Finally, operating system is advised not to swap the memory to disk, or
//! include it in crash reports/core dumps.
//!
//! Hard also provides an interface for marking memory as read-only/no-access when its
//! modification/access is not required. This can be used to protect sensitive data from access
//! while not in use.
//!
//! # Examples
//! ```rust
//! use hard::{buffer_type, Buffer, BufferMut};
//!
//! // Create a new public buffer type, which will store 32 bytes (= 256 bits) of sensitive data:
//! buffer_type! {
//!     /// Stores a 256-bit key.
//!     pub Key(32);
//! }
//!
//! // The new type implements a couple of basic traits for its construction and initialisation:
//! let mut my_key = Key::new().unwrap();
//! my_key.zero();
//!
//! // It also implements `Deref`, and similar types associated with smart pointers, so we can
//! // treat it like an array [u8; 32]:
//! my_key.copy_from_slice(b"Some data to store in the buffer");
//! my_key[0] ^= 0xab;
//! my_key[1] ^= 0xcd;
//!
//! // Mark the buffer as read-only, which will prevent modification to its contents:
//! let my_key = my_key.into_readonly().unwrap();
//!
//! // When the buffer is dropped, its contents are securely erased, preventing leakage of the
//! // contents via uninitialised memory.
//! ```
//!
//! We can also create anonymous buffers, which provide access to hardened memory without the need
//! to worry about creating new types for whatever operation we perform:
//!
//! ```rust
//! use hard::{buffer, Buffer, BufferMut};
//!
//! // Create a 512 byte buffer.
//! let mut some_data = buffer!(512).unwrap();
//!
//! // Copy in some data
//! some_data.copy_from_slice(&[0xab; 512]);
//!
//! // Debugging a buffer does not directly print its contents, although deref'ing it does do so.
//! println!("{:?}, {:?}", some_data, *some_data);
//!
//! // Once again, dropping the buffer erases its contents.
//! ```
//!
//! For more information, see the [`buffer`] and [`buffer_type`] macros, and the traits the buffer
//! types implement: [`Buffer`], [`BufferMut`], [`BufferReadOnly`], [`BufferNoAccess`].
pub mod mem;

pub use paste;

use errno::Errno;
use libsodium_sys as sodium;
use thiserror::Error;

/// Represents an error encountered while using Hard.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum HardError {
    /// `sodium_malloc` returned an error when we tried to allocate a region of memory.
    ///
    /// This is most likely to occur if there is not sufficient memory to allocate, but could occur
    /// for other reasons. The associated value contains the value of the errno value, which is set
    /// if `sodium_malloc` fails.
    #[error("Failed to allocate secure memory region")]
    AllocationFailed(Errno),

    /// `sodium_mprotect_noaccess` returned an error.
    ///
    /// This is most likely to occur if the platform we're running on doesn't have the `mprotect`
    /// syscall (or its equivalent).
    #[error("Failed to mark memory region as noaccess (syscall may not be available)")]
    MprotectNoAccessFailed(Errno),

    /// `sodium_mprotect_readonly` returned an error.
    ///
    /// This is most likely to occur if the platform we're running on doesn't have the `mprotect`
    /// syscall (or its equivalent).
    #[error("Failed to mark memory region as readonly (syscall may not be available)")]
    MprotectReadOnlyFailed(Errno),

    /// `sodium_mprotect_readwrite` returned an error.
    ///
    /// This is most likely to occur if the platform we're running on doesn't have the `mprotect`
    /// syscall (or its equivalent).
    #[error("Failed to mark memory region as read/write (syscall may not be available)")]
    MprotectReadWriteFailed(Errno),

    /// `sodium_init` returned an error.
    #[error("Failed to initialise libsodium")]
    InitFailed,
}

/// Trait implemented by any buffer type generated with [`buffer_type`].
pub trait Buffer
where
    Self: Sized,
{
    /// The size of this buffer, in bytes.
    const SIZE: usize;

    /// Create a new instance of the buffer, filled with garbage data.
    fn new() -> Result<Self, HardError>;
}

/// Trait implemented by any buffer type with mutable contents.
pub trait BufferMut: Buffer
where
    Self: Sized,
{
    /// The variant of this buffer that is locked such that its contents cannot be accessed.
    type NoAccess: BufferNoAccess;

    /// The variant of this buffer that is locked such that its contents cannot be mutated,
    /// although they can be read.
    type ReadOnly: BufferReadOnly;

    /// Overwrite the contents of the buffer with zeros, in such a way that will not be optimised
    /// away by the compiler.
    ///
    /// Buffers are automatically zeroed on drop, you should not need to call this method yourself
    /// unless you want to set a buffer to zero for initialisation purposes.
    fn zero(&mut self);

    /// Attempt to clone this buffer.
    ///
    /// This will allocate a new region of memory, and copy the contents of this buffer into it.
    fn try_clone(&self) -> Result<Self, HardError>;

    /// `mprotect` the region of memory pointed to by this buffer, so that it cannot be accessed.
    ///
    /// This function uses the operating system's memory protection tools to mark the region of
    /// memory backing this buffer as inaccessible. This is used as a hardening measure, to protect
    /// the region of memory so that it can't be accessed by anything while we don't need it.
    ///
    /// If there is no `mprotect` (or equivalent) syscall on this platform, this function will
    /// return an error.
    fn into_noaccess(self) -> Result<Self::NoAccess, HardError>;

    /// `mprotect` the region of memory pointed to by this buffer, so that it cannot be mutated,
    /// although it can still be read.
    ///
    /// This function uses the operating system's memory protection tools to mark the region of
    /// memory backing this buffer as read-only. This is used as a hardening measure, to protect
    /// the region of memory so that it can't be altered by anything. This would be well suited to,
    /// for example, secure a key after key generation, since there is no need to modify a key once
    /// we've generated it in most cases.
    ///
    /// If there is no `mprotect` (or equivalent) syscall on this platform, this function will
    /// return an error.
    fn into_readonly(self) -> Result<Self::ReadOnly, HardError>;
}

/// Trait implemented by any buffer type whose memory is marked no-access.
pub trait BufferNoAccess: Buffer
where
    Self: Sized,
{
    /// The mutable variant of this buffer.
    type ReadWrite: BufferMut;

    /// The variant of this buffer that is locked such that its contents cannot be mutated,
    /// although they can be read.
    type ReadOnly: BufferReadOnly;

    /// Remove protections for this buffer that marked it as noaccess, so it can be read and
    /// modified.
    ///
    /// This basically just marks the memory underlying this buffer as the same as any normal
    /// memory, so it can be read or modified again, although sodium's hardening measures (guard
    /// pages, canaries, mlock, etc.) remain in place.
    ///
    /// If there is no `mprotect` (or equivalent) syscall on this platform, this function will
    /// return an error.
    fn into_mut(self) -> Result<Self::ReadWrite, HardError>;

    /// `mprotect` the region of memory pointed to by this buffer, so that it cannot be mutated,
    /// although it can still be read.
    ///
    /// This function uses the operating system's memory protection tools to mark the region of
    /// memory backing this buffer as read-only. This is used as a hardening measure, to protect
    /// the region of memory so that it can't be altered by anything. This would be well suited to,
    /// for example, secure a key after key generation, since there is no need to modify a key once
    /// we've generated it in most cases.
    ///
    /// If there is no `mprotect` (or equivalent) syscall on this platform, this function will
    /// return an error.
    fn into_readonly(self) -> Result<Self::ReadOnly, HardError>;
}

/// Trait implemented by any buffer type whose memory is marked read-only.
pub trait BufferReadOnly: Buffer
where
    Self: Sized,
{
    /// The mutable variant of this buffer.
    type ReadWrite: BufferMut;

    /// The variant of this buffer that is locked such that its contents cannot be accessed.
    type NoAccess: BufferNoAccess;

    /// Attempt to clone this buffer.
    ///
    /// This will allocate a new region of memory, and copy the contents of this buffer into it.
    fn try_clone(&self) -> Result<Self, HardError>;

    /// Remove protections for this buffer that marked it as noaccess, so it can be read and
    /// modified.
    ///
    /// This basically just marks the memory underlying this buffer as the same as any normal
    /// memory, so it can be read or modified again, although sodium's hardening measures (guard
    /// pages, canaries, mlock, etc.) remain in place.
    ///
    /// If there is no `mprotect` (or equivalent) syscall on this platform, this function will
    /// return an error.
    fn into_mut(self) -> Result<Self::ReadWrite, HardError>;

    /// `mprotect` the region of memory pointed to by this buffer, so that it cannot be accessed.
    ///
    /// This function uses the operating system's memory protection tools to mark the region of
    /// memory backing this buffer as inaccessible. This is used as a hardening measure, to protect
    /// the region of memory so that it can't be accessed by anything while we don't need it.
    ///
    /// If there is no `mprotect` (or equivalent) syscall on this platform, this function will
    /// return an error.
    fn into_noaccess(self) -> Result<Self::NoAccess, HardError>;
}

#[doc(hidden)]
pub unsafe trait BufferAsPtr: Buffer
where
    Self: Sized,
{
    /// Returns the pointer to the memory backing this type.
    ///
    /// We use this to implement PartialEq for buffer types using `sodium_memcmp`, which needs a
    /// pointer to both portions of memory we're comparing.
    ///
    /// # Safety
    /// This function returns a pointer to raw memory, any modification to its contents or
    /// protection status could violate the safety invariants required for this buffer type to be
    /// safe. Therefore, it should only be used where the memory it points to will not be modified,
    /// and any use should be documented.
    unsafe fn as_ptr(&self) -> std::ptr::NonNull<()>;
}

#[macro_export]
#[doc(hidden)]
macro_rules! buffer_common_impl {
    ($name:ident, $size:expr) => {
        impl Drop for $name {
            fn drop(&mut self) {
                // SAFETY:
                //  * Is a double-free possible in safe code?
                //    * No: `drop` cannot be called manually, and is only called once when the
                //      buffer is actually dropped. Once the value is dropped, there's no way to
                //      free the memory again. In methods that produce other buffers (e.g:
                //      `try_clone`, `into_noaccess`), we either allocate new memory for the new
                //      buffer, or use `ManuallyDrop` to avoid calling drop more than once.
                //  * Is a use-after-free possible in safe code?
                //    * No: We only ever free a buffer on drop. and after drop, the buffer type is
                //      no longer accessible.
                //  * Is a memory leak possible in safe code?
                //    * Yes: If the user uses `Box::leak()`, `ManuallyDrop`, or `std::mem::forget`,
                //      the destructor will not be called even though the buffer is dropped.
                //      However, it is documented that in these cases heap memory may be leaked, so
                //      this is expected behaviour. In addition, certain signal interrupts, or
                //      setting panic=abort, will mean that the destructor is not called. In any
                //      other case, `drop` will be called, and the memory freed.
                unsafe {
                    $crate::mem::free(self.0);
                }
            }
        }
    };
}

#[macro_export]
#[doc(hidden)]
macro_rules! buffer_immutable_impl {
    ($name:ident, $size:expr) => {
        #[doc(hidden)]
        unsafe impl $crate::BufferAsPtr for $name {
            unsafe fn as_ptr(&self) -> std::ptr::NonNull<()> {
                self.0.cast()
            }
        }

        impl std::convert::AsRef<[u8; $size]> for $name {
            fn as_ref(&self) -> &[u8; $size] {
                // SAFETY: As long as a buffer type exists, the memory backing it is
                // dereferenceable and non-null. The lifetime of the returned reference is that of
                // the struct, as the memory is only freed on drop. Any portion of memory of length
                // T is a valid array of `u8`s of size T, so initialisation & alignment issues are
                // not a concern.
                unsafe { self.0.as_ref() }
            }
        }

        impl std::borrow::Borrow<[u8; $size]> for $name {
            fn borrow(&self) -> &[u8; $size] {
                // SAFETY: As long as a buffer type exists, the memory backing it is
                // dereferenceable and non-null. The lifetime of the returned reference is that of
                // the struct, as the memory is only freed on drop. Any portion of memory of length
                // T is a valid array of `u8`s of size T, so initialisation & alignment issues are
                // not a concern.
                unsafe { self.0.as_ref() }
            }
        }

        impl std::fmt::Debug for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str(&format!("{}([u8; {}])", stringify!($name), $size))
            }
        }

        impl std::ops::Deref for $name {
            type Target = [u8; $size];

            fn deref(&self) -> &Self::Target {
                // SAFETY: As long as a buffer type exists, the memory backing it is
                // dereferenceable and non-null. The lifetime of the returned reference is that of
                // the struct, as the memory is only freed on drop. Any portion of memory of length
                // T is a valid array of `u8`s of size T, so initialisation & alignment issues are
                // not a concern.
                unsafe { self.0.as_ref() }
            }
        }

        impl<T: $crate::Buffer + $crate::BufferAsPtr> std::cmp::PartialEq<T> for $name {
            fn eq(&self, other: &T) -> bool {
                if T::SIZE != Self::SIZE {
                    return false;
                }

                // SAFETY: We make use of the unsafe method `Self::as_ptr` here, which requires
                // that we do not modify the memory to which its return value points. The `memcmp`
                // function simply compares two pointers, they will not be modified. As both `self`
                // and `other` are instances of a Buffer, we know they must point to sufficient,
                // allocated memory for their types, so the memcmp call is safe.
                unsafe { $crate::mem::memcmp(self.0, other.as_ptr().cast()) }
            }
        }

        impl std::fmt::Pointer for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
                <std::ptr::NonNull<[u8; $size]> as std::fmt::Pointer>::fmt(&self.0, f)
            }
        }
    };
}

#[macro_export]
#[doc(hidden)]
macro_rules! buffer_mutable_impl {
    ($name:ident, $size:expr) => {
        $crate::paste::paste! {
            $crate::buffer_common_impl!($name, $size);
            $crate::buffer_immutable_impl!($name, $size);

            impl $crate::Buffer for $name {
                const SIZE: usize = $size;

                fn new() -> Result<Self, $crate::HardError> {
                    $crate::init()?;
                    // SAFETY: This call to malloc() will allocate the memory required for a [u8;
                    // $size] type, outside of Rust's memory management. The associated memory is
                    // always freed in the corresponding `drop` call. We never free the memory in
                    // any other method of this struct, nor do we ever give out a pointer to the
                    // memory directly, only references. The region of memory allocated will always
                    // a valid representation of a [u8; $size], as a [u8; $size] is simply
                    // represented as $size bytes of memory, of arbitrary values. The alignment for
                    // a u8 is just 1, so we don't need to worry about alignment issues.
                    let ptr = unsafe { $crate::mem::malloc()? };
                    Ok(Self(ptr))
                }
            }

            impl $crate::BufferMut for $name {
                type NoAccess = [<$name NoAccess>];

                type ReadOnly = [<$name ReadOnly>];

                fn zero(&mut self) {
                    // SAFETY: While a buffer is in scope, its memory is valid. It is therefore
                    // safe to write zeroes to the buffer. All zeroes is a valid memory
                    // representation of a u8 array.
                    unsafe { $crate::mem::memzero(self.0) }
                }

                fn try_clone(&self) -> Result<Self, $crate::HardError> {
                    let mut new_buf = Self::new()?;
                    new_buf.copy_from_slice(self.as_ref());
                    Ok(new_buf)
                }

                fn into_noaccess(self) -> Result<Self::NoAccess, $crate::HardError> {
                    // SAFETY: Avoid calling self.drop() when self goes out of scope, so as to
                    // avoid freeing the underlying memory. We use the underlying memory in the new
                    // type, so when it goes out of scope, the memory will then be freed.
                    let self_leak = std::mem::ManuallyDrop::new(self);
                    // SAFETY: The buffer is currently in scope, so its backing memory is valid.
                    unsafe { $crate::mem::mprotect_noaccess(self_leak.0)?; }
                    Ok([<$name NoAccess>](self_leak.0))
                }

                fn into_readonly(self) -> Result<Self::ReadOnly, $crate::HardError> {
                    // SAFETY: Avoid calling self.drop() when self goes out of scope, so as to
                    // avoid freeing the underlying memory. We use the underlying memory in the new
                    // type, so when it goes out of scope, the memory will then be freed.
                    let self_leak = std::mem::ManuallyDrop::new(self);
                    // SAFETY: The buffer is currently in scope, so its backing memory is valid.
                    unsafe { $crate::mem::mprotect_readonly(self_leak.0)?; }
                    Ok([<$name ReadOnly>](self_leak.0))
                }
            }

            impl std::convert::AsMut<[u8; $size]> for $name {
                fn as_mut(&mut self) -> &mut [u8; $size] {
                    // SAFETY: As long as a buffer type exists, the memory backing it is
                    // dereferenceable and non-null. The lifetime of the returned reference is that
                    // of the struct, as the memory is only freed on drop. Any portion of memory of
                    // length T is a valid array of `u8`s of size T, so initialisation & alignment
                    // issues are not a concern.
                    unsafe { self.0.as_mut() }
                }
            }

            impl std::borrow::BorrowMut<[u8; $size]> for $name {
                fn borrow_mut(&mut self) -> &mut [u8; $size] {
                    // SAFETY: As long as a buffer type exists, the memory backing it is
                    // dereferenceable and non-null. The lifetime of the returned reference is that
                    // of the struct, as the memory is only freed on drop. Any portion of memory of
                    // length T is a valid array of `u8`s of size T, so initialisation & alignment
                    // issues are not a concern.
                    unsafe { self.0.as_mut() }
                }
            }

            impl std::ops::DerefMut for $name {
                fn deref_mut(&mut self) -> &mut Self::Target {
                    // SAFETY: As long as a buffer type exists, the memory backing it is
                    // dereferenceable and non-null. The lifetime of the returned reference is that
                    // of the struct, as the memory is only freed on drop. Any portion of memory of
                    // length T is a valid array of `u8`s of size T, so initialisation & alignment
                    // issues are not a concern.
                    unsafe { self.0.as_mut() }
                }
            }
        }
    };
}

#[macro_export]
#[doc(hidden)]
macro_rules! buffer_noaccess_impl {
    ($name:ident, $size:expr) => {
        $crate::paste::paste! {
            $crate::buffer_common_impl!([<$name NoAccess>], $size);

            impl $crate::Buffer for [<$name NoAccess>] {
                const SIZE: usize = $size;

                fn new() -> Result<Self, $crate::HardError> {
                    $crate::init()?;
                    // SAFETY: This call to malloc() will allocate the memory required for a [u8;
                    // $size] type, outside of Rust's memory management. The associated memory is
                    // always freed in the corresponding `drop` call. We never free the memory in
                    // any other method of this struct, nor do we ever give out a pointer to the
                    // memory directly, only references. The region of memory allocated will always
                    // a valid representation of a [u8; $size], as a [u8; $size] is simply
                    // represented as $size bytes of memory, of arbitrary values. The alignment for
                    // a u8 is just 1, so we don't need to worry about alignment issues.
                    let ptr = unsafe {
                        let ptr = $crate::mem::malloc()?;
                        $crate::mem::mprotect_noaccess(ptr)?;
                        ptr
                    };
                    Ok(Self(ptr))
                }
            }

            impl $crate::BufferNoAccess for [<$name NoAccess>] {
                type ReadWrite = $name;

                type ReadOnly = [<$name ReadOnly>];

                fn into_mut(self) -> Result<Self::ReadWrite, $crate::HardError> {
                    // SAFETY: Avoid calling self.drop() when self goes out of scope, so as to
                    // avoid freeing the underlying memory. We use the underlying memory in the new
                    // type, so when it goes out of scope, the memory will then be freed.
                    let self_leak = std::mem::ManuallyDrop::new(self);
                    // SAFETY: The buffer is currently in scope, so its backing memory is valid.
                    unsafe { $crate::mem::mprotect_readwrite(self_leak.0)?; }
                    Ok($name(self_leak.0))
                }

                fn into_readonly(self) -> Result<Self::ReadOnly, $crate::HardError> {
                    // SAFETY: Avoid calling self.drop() when self goes out of scope, so as to
                    // avoid freeing the underlying memory. We use the underlying memory in the new
                    // type, so when it goes out of scope, the memory will then be freed.
                    let self_leak = std::mem::ManuallyDrop::new(self);
                    // SAFETY: The buffer is currently in scope, so its backing memory is valid.
                    unsafe { $crate::mem::mprotect_readonly(self_leak.0)?; }
                    Ok([<$name ReadOnly>](self_leak.0))
                }
            }
        }
    };
}

#[macro_export]
#[doc(hidden)]
macro_rules! buffer_readonly_impl {
    ($name:ident, $size:expr) => {
        $crate::paste::paste! {
            $crate::buffer_common_impl!([<$name ReadOnly>], $size);
            $crate::buffer_immutable_impl!([<$name ReadOnly>], $size);

            impl $crate::Buffer for [<$name ReadOnly>] {
                const SIZE: usize = $size;

                fn new() -> Result<Self, $crate::HardError> {
                    $crate::init()?;
                    // SAFETY: This call to malloc() will allocate the memory required for a [u8;
                    // $size] type, outside of Rust's memory management. The associated memory is
                    // always freed in the corresponding `drop` call. We never free the memory in
                    // any other method of this struct, nor do we ever give out a pointer to the
                    // memory directly, only references. The region of memory allocated will always
                    // a valid representation of a [u8; $size], as a [u8; $size] is simply
                    // represented as $size bytes of memory, of arbitrary values. The alignment for
                    // a u8 is just 1, so we don't need to worry about alignment issues.
                    let ptr = unsafe {
                        let ptr = $crate::mem::malloc()?;
                        $crate::mem::mprotect_readonly(ptr)?;
                        ptr
                    };
                    Ok(Self(ptr))
                }
            }

            impl $crate::BufferReadOnly for [<$name ReadOnly>] {
                type ReadWrite = $name;

                type NoAccess = [<$name NoAccess>];

                fn try_clone(&self) -> Result<Self, $crate::HardError> {
                    use $crate::BufferMut;

                    let mut new_buf = $name::new()?;
                    new_buf.copy_from_slice(self.as_ref());
                    new_buf.into_readonly()
                }

                fn into_mut(self) -> Result<Self::ReadWrite, $crate::HardError> {
                    // SAFETY: Avoid calling self.drop() when self goes out of scope, so as to
                    // avoid freeing the underlying memory. We use the underlying memory in the new
                    // type, so when it goes out of scope, the memory will then be freed.
                    let self_leak = std::mem::ManuallyDrop::new(self);
                    // SAFETY: The buffer is currently in scope, so its backing memory is valid.
                    unsafe { $crate::mem::mprotect_readwrite(self_leak.0)?; }
                    Ok($name(self_leak.0))
                }

                fn into_noaccess(self) -> Result<Self::NoAccess, $crate::HardError> {
                    // SAFETY: Avoid calling self.drop() when self goes out of scope, so as to
                    // avoid freeing the underlying memory. We use the underlying memory in the new
                    // type, so when it goes out of scope, the memory will then be freed.
                    let self_leak = std::mem::ManuallyDrop::new(self);
                    // SAFETY: The buffer is currently in scope, so its backing memory is valid.
                    unsafe { $crate::mem::mprotect_noaccess(self_leak.0)?; }
                    Ok([<$name NoAccess>](self_leak.0))
                }
            }
        }
    };
}

/// Create a new fixed-size buffer type.
///
/// `buffer_type!(Name(Size))` will create a new type with name `Name`, that provides access to
/// `Size` bytes of hardened contiguous memory.
///
/// The new type will implement the following traits:
///  * [`Buffer`] and [`BufferMut`]
///  * [`AsRef<[u8; Size]>`](std::convert::AsRef) and [`AsMut<[u8; Size]>`](std::convert::AsMut)
///  * [`Borrow<[u8; $size]>`](std::borrow::Borrow) and [`BorrowMut<[u8;
///  * [`Debug`](std::fmt::Debug)
///  * [`Deref<Target = [u8; Size]>`](std::ops::Deref) and [`DerefMut`](std::ops::DerefMut)
///    $size]>`](std::borrow::BorrowMut)
///  * [`PartialEq<Rhs = BufferMut or BufferReadOnly>`](std::cmp::PartialEq) and
///    [`Eq`](std::cmp::Eq)
///    * This implementation uses a constant-time comparison function for equivalent-sized buffers,
///      suitable for comparing sensitive data without the risk of timing attacks.
///  * [`Pointer`](std::fmt::Pointer)
///
/// This macro also generates `NameNoAccess` and `NameReadOnly` variants, which use the operating
/// system's memory protection utilities to mark the buffer's contents as completely inaccessible,
/// and immutable, respectively.
///
/// ## Example Usage
/// ```rust
/// use hard::{buffer_type, Buffer};
///
/// // Create a 32-byte (256-bit) buffer type called `Key`
/// buffer_type!(Key(32));
/// let mut my_key = Key::new().unwrap();
/// // The type implements Deref<Target = [u8; 32]> and DerefMut, so we can use any methods from
/// // the array type.
/// my_key.copy_from_slice(b"Some data to copy into my_key...");
/// my_key[0] ^= 0xca;
/// println!("{:x?}", my_key);
///
/// // By default, a new buffer type will be private, but we can specify that it should be public.
/// buffer_type!(pub Password(128));
///
/// // We can also provide documentation for the newly generated type, if we like.
/// buffer_type! {
///     /// This type stores some very important information
///     pub ImportantBuf(99);
/// }
/// ```
#[macro_export]
macro_rules! buffer_type {
    ($(#[$metadata:meta])* $name:ident($size:expr)$(;)?) => {
        $crate::paste::paste! {
            $(#[$metadata])*
            struct $name(std::ptr::NonNull<[u8; $size]>);
            $crate::buffer_mutable_impl!($name, $size);

            /// Variation of this buffer type whose contents are restricted from being accessed.
            struct [<$name NoAccess>](std::ptr::NonNull<[u8; $size]>);
            $crate::buffer_noaccess_impl!($name, $size);

            /// Variation of this buffer type whose contents are restricted from being mutated.
            struct [<$name ReadOnly>](std::ptr::NonNull<[u8; $size]>);
            $crate::buffer_readonly_impl!($name, $size);
        }
    };
    ($(#[$metadata:meta])* pub $name:ident($size:expr)$(;)?) => {
        $crate::paste::paste! {
            $(#[$metadata])*
            pub struct $name(std::ptr::NonNull<[u8; $size]>);
            $crate::buffer_mutable_impl!($name, $size);

            /// Variation of this buffer type whose contents are restricted from being accessed.
            pub struct [<$name NoAccess>](std::ptr::NonNull<[u8; $size]>);
            $crate::buffer_noaccess_impl!($name, $size);

            /// Variation of this buffer type whose contents are restricted from being mutated.
            pub struct [<$name ReadOnly>](std::ptr::NonNull<[u8; $size]>);
            $crate::buffer_readonly_impl!($name, $size);
        }
    };
}

/// Create a fixed-size anonymous buffer.
///
/// `buffer!(Size)` will initialise a new buffer of length `Size` bytes, returning
/// `Result<Buffer, HardError>`.
///
/// The buffer will implement the following traits:
///  * [`Buffer`] and [`BufferMut`]
///  * [`AsRef<[u8; Size]>`](std::convert::AsRef) and [`AsMut<[u8; Size]>`](std::convert::AsMut)
///  * [`Borrow<[u8; $size]>`](std::borrow::Borrow) and [`BorrowMut<[u8;
///  * [`Debug`](std::fmt::Debug)
///  * [`Deref<Target = [u8; Size]>`](std::ops::Deref) and [`DerefMut`](std::ops::DerefMut)
///    $size]>`](std::borrow::BorrowMut)
///  * [`PartialEq<Rhs = BufferMut or BufferReadOnly>`](std::cmp::PartialEq) and
///    [`Eq`](std::cmp::Eq)
///    * This implementation uses a constant-time comparison function, suitable for comparing
///      sensitive data without the risk of timing attacks.
///  * [`Pointer`](std::fmt::Pointer)
///
/// ## Example Usage
/// ```rust
/// use hard::buffer;
///
/// // Create a 32-byte buffer
/// let mut some_buffer = buffer!(32).unwrap();
/// some_buffer.copy_from_slice(b"Copy this data into that buffer.");
///
/// let mut another_buffer = buffer!(32).unwrap();
/// some_buffer.copy_from_slice(b"We'll compare these two buffers.");
///
/// // This comparison is a constant-time equality-check of the contents of the two buffers
/// assert!(some_buffer != another_buffer);
/// ```
#[macro_export]
macro_rules! buffer {
    ($size:expr$(;)?) => {{
        $crate::paste::paste! {
            use $crate::Buffer;
            $crate::buffer_type!([<_HardAnonBuffer $size>]($size));
            [<_HardAnonBuffer $size>]::new()
        }
    }};
}

/// Initialise Sodium.
///
/// This function is automatically called when a buffer is initialised. It can safely be called
/// multiple times from multiple threads. You should not need to call this function yourself, but
/// it's not an issue if you do.
pub fn init() -> Result<(), HardError> {
    // SAFETY: Sodium guarantees that this function is thread safe, and can be called multiple
    // times without issue. It should not produce any unsafe behaviour. If it returns a
    // non-negative value, then Sodium has been securely initialised, and can be used throughout
    // the program.
    unsafe {
        if sodium::sodium_init() >= 0 {
            Ok(())
        } else {
            Err(HardError::InitFailed)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        buffer, buffer_type, init, Buffer, BufferMut, BufferNoAccess, BufferReadOnly, HardError,
    };
    use std::borrow::{Borrow, BorrowMut};
    use std::ops::DerefMut;

    #[test]
    fn initialise_sodium() -> Result<(), HardError> {
        init()
    }

    #[test]
    fn create_buffer_types() -> Result<(), HardError> {
        buffer_type!(Buf8(8));
        buffer_type!(pub Buf32(32));
        buffer_type! {
            /// Documented
            Buf512(512)
        }
        buffer_type! {
            /// Public and documented
            pub Buf1MiB(1 << 20)
        }

        assert_eq!(Buf8::SIZE, 8);
        assert_eq!(Buf32::SIZE, 32);
        assert_eq!(Buf512::SIZE, 512);
        assert_eq!(Buf1MiB::SIZE, 1 << 20);

        let buf_8 = Buf8::new()?;
        let buf_32 = Buf32::new()?;
        let buf_512 = Buf512::new()?;
        let buf_mib = Buf1MiB::new()?;

        assert_eq!(buf_8.len(), 8);
        assert_eq!(buf_32.len(), 32);
        assert_eq!(buf_512.len(), 512);
        assert_eq!(buf_mib.len(), 1 << 20);

        Ok(())
    }

    #[test]
    fn create_anonymous_buffers() -> Result<(), HardError> {
        let buf_8_a = buffer!(8)?;
        let buf_8_b = buffer!(8)?;
        let buf_32 = buffer!(32)?;
        let buf_512 = buffer!(512)?;
        let buf_mib = buffer!(0x100000)?;

        assert_eq!(buf_8_a.len(), 8);
        assert_eq!(buf_8_b.len(), 8);
        assert_eq!(buf_32.len(), 32);
        assert_eq!(buf_512.len(), 512);
        assert_eq!(buf_mib.len(), 1 << 20);

        Ok(())
    }

    #[test]
    fn buffer_traits() -> Result<(), HardError> {
        let mut buf = buffer!(32)?;
        buf.zero();

        let buf_b = buf.try_clone()?;
        assert_eq!(buf, buf_b);

        let buf = buf.into_noaccess()?;
        let buf = buf.into_mut()?;
        let buf = buf.into_readonly()?;

        let buf_c = buf.try_clone()?;
        assert_eq!(buf, buf_c);

        let buf = buf.into_noaccess()?;
        let buf = buf.into_readonly()?;
        let buf = buf.into_mut()?;

        assert_eq!(*buf, [0; 32]);

        Ok(())
    }

    #[test]
    fn immutable_common_trait_impls() -> Result<(), HardError> {
        let mut buf = buffer!(32)?;
        buf.zero();

        // AsRef
        assert_eq!(buf.as_ref(), &[0; 32]);
        // Borrow
        let buf_ref: &[u8; 32] = buf.borrow();
        assert_eq!(buf_ref, &[0; 32]);
        // Debug
        format!("{:?}", buf);
        // Deref
        assert_eq!(*buf, [0; 32]);
        // PartialEq
        let mut other = buffer!(32)?;
        other.zero();
        assert_eq!(buf, other);
        // Pointer
        format!("{:p}", buf);

        Ok(())
    }

    #[test]
    fn mutable_common_trait_impls() -> Result<(), HardError> {
        let mut buf = buffer!(32)?;
        buf.zero();

        // AsMut
        assert_eq!(buf.as_mut(), &mut [0; 32]);
        // BorrowMut
        let buf_ref: &mut [u8; 32] = buf.borrow_mut();
        assert_eq!(buf_ref, &mut [0; 32]);
        // DerefMut
        assert_eq!(buf.deref_mut(), &mut [0; 32]);

        Ok(())
    }
}
