//! Low level memory-management utilities.
//!
//! You probably don't want to use these directly, the rest of this crate provides much safer
//! abstractions for interacting with memory.
use super::HardError;
use errno::errno;
use libsodium_sys as sodium;
use std::ffi::c_void;
use std::ptr::NonNull;

/// Allocate sufficient hardened memory to store a value of type `T`, returning a pointer to the
/// start of the allocated memory.
///
/// Uses the Sodium function `sodium_malloc` to securely allocate a region of memory, which will be
/// `mlock`ed, and surrounded with guard pages.
///
/// Returns `Ok(ptr)`, where `ptr` is a pointer to the newly-allocated memory, if allocation was
/// successful, otherwise returns a [`HardError`].
///
/// # Safety
/// This function returns a pointer to uninitialised memory, allocated outside of Rust's memory
/// management. As such, all the issues associated with manual memory management in languages like
/// C apply: Memory must be initialised before use, it must be freed exactly once, and not used
/// after having been freed. Memory allocated with this function should be freed using [`free`]
/// from this module, rather than any other memory management tool, to preserve Sodium's security
/// invariants.
///
/// You must call [`super::init`] before using this function.
pub unsafe fn malloc<T>() -> Result<NonNull<T>, HardError> {
    // Returns a `*mut c_void`, cast to `*mut ()`. If allocation is successful, this will be a
    // pointer to sufficient allocated memory to store a `T` value. Otherwise, it will be NULL, and
    // errno should be set.
    let ptr = sodium::sodium_malloc(std::mem::size_of::<T>()) as *mut ();
    // We use the `NonNull::new` method, which returns `None` in the case that we pass it a NULL
    // pointer, to detect the case where allocation fails.
    NonNull::new(ptr)
        .map(|p| p.cast())
        .ok_or(HardError::AllocationFailed(errno()))
}

/// Free the memory pointed to by `ptr`, previously allocated using [`malloc`] from this module.
///
/// Uses the Sodium function `sodium_free` to securely zero and deallocate memory previously
/// allocated using `sodium_malloc`.
///
/// # Safety
/// This function should only be called with a pointer to memory previously allocated using
/// [`malloc`] from this module. This function will cause the program to exit if a buffer overrun
/// is detected (i.e: the canary placed next to the allocated region has been overwritten).
///
/// You must call [`super::init`] before using this function.
pub unsafe fn free<T>(ptr: NonNull<T>) {
    // `sodium_free` has no return type in libsodium: It will simply exit if there is an error, as
    // there can only be an error if something dangerous has occurred.
    sodium::sodium_free(ptr.as_ptr() as *mut c_void)
}

/// Zero the memory region pointed to by `ptr`.
///
/// Uses `sodium_memzero` to zero memory in such a way that the compiler will not optimise away the
/// opteration.
///
/// # Safety
/// This function should only be called with a pointer to at least `size` bytes of allocated,
/// writeable memory, where `size` is the size of a value of type `T`. If `size` is larger than the
/// allocated region, undefined behaviour will occur.
///
/// You must call [`super::init`] before using this function.
pub unsafe fn memzero<T>(ptr: NonNull<T>) {
    sodium::sodium_memzero(ptr.as_ptr() as *mut c_void, std::mem::size_of::<T>())
}

/// Compare two regions of memory for equality in constant-time.
///
/// Uses `sodium_memcmp` for constant-time comparison of two memory regions, to prevent timing
/// attacks. The length of the region compared is determined by the size of the type `T`. Returns
/// true if the contents of the memory regions are equal, false otherwise.
///
/// # Safety
/// Both `a` and `b` must be pointers to regions of allocated memory of length at least `size`
/// bytes, where `size` is the size of a value of type `T`.
///
/// You must call [`super::init`] before using this function.
pub unsafe fn memcmp<T>(a: NonNull<T>, b: NonNull<T>) -> bool {
    sodium::sodium_memcmp(
        a.as_ptr() as *const c_void,
        b.as_ptr() as *const c_void,
        std::mem::size_of::<T>(),
    ) == 0
}

/// Sets a region of memory allocated with libsodium to be inaccessible.
///
/// This is used to protect a buffer when its contents are not required for any operations. When it
/// is next needed, its contents can be marked readable or mutable via [`mprotect_readonly`] or
/// [`mprotect_readwrite`].
///
/// # Safety
/// `ptr` must be a pointer to memory allocated using [`malloc`] from libsodium, and must point to
/// at least `size` bytes of allocated memory, where size is the size of a value of type `T`. After
/// this function is called, any attempt to access the associated memory will result in the
/// immediate termination of the program, unless its protected status is changed.
///
/// You must call [`super::init`] before using this function.
pub unsafe fn mprotect_noaccess<T>(ptr: NonNull<T>) -> Result<(), HardError> {
    if sodium::sodium_mprotect_noaccess(ptr.as_ptr() as *mut c_void) == 0 {
        Ok(())
    } else {
        Err(HardError::MprotectNoAccessFailed(errno()))
    }
}

/// Sets a region of memory allocated with libsodium to be readable, but not mutable.
///
/// This is used to protect a buffer when its contents do not need to be modified, but its value is
/// still required to be used. If it needs to be modified, its contents can be marked mutable via
/// [`mprotect_readwrite`]. If there is a period of time for which it does not need to be read or
/// modified, it can be marked as no access via [`mprotect_noaccess`].
///
/// # Safety
/// `ptr` must be a pointer to memory allocated using [`malloc`] from libsodium, and must point to
/// at least `size` bytes of allocated memory, where size is the size of a value of type `T`. After
/// this function is called, any attempt to mutate the associated memory will result in the
/// immediate termination of the program, unless its protected status is changed.
///
/// You must call [`super::init`] before using this function.
pub unsafe fn mprotect_readonly<T>(ptr: NonNull<T>) -> Result<(), HardError> {
    if sodium::sodium_mprotect_readonly(ptr.as_ptr() as *mut c_void) == 0 {
        Ok(())
    } else {
        Err(HardError::MprotectReadOnlyFailed(errno()))
    }
}

/// Sets a region of memory allocated with libsodium to be readable and writeable.
///
/// This is used after we have already invoked [`mprotect_noaccess`] or [`mprotect_readonly`] to
/// reset the region to its normal (mutable) state.
///
/// # Safety
/// `ptr` must be a pointer to memory allocated using [`malloc`] from libsodium, and must point to
/// at least `size` bytes of allocated memory, where size is the size of a value of type `T`.
///
/// You must call [`super::init`] before using this function.
pub unsafe fn mprotect_readwrite<T>(ptr: NonNull<T>) -> Result<(), HardError> {
    if sodium::sodium_mprotect_readwrite(ptr.as_ptr() as *mut c_void) == 0 {
        Ok(())
    } else {
        Err(HardError::MprotectReadWriteFailed(errno()))
    }
}

#[cfg(test)]
mod tests {
    // This set of tests relies on having at least 1 MiB of memory available to allocate.
    // Therefore, these tests may fail on platforms with very limited resources.
    use super::*;
    use crate::{init, HardError};
    use std::ptr::NonNull;

    #[test]
    fn malloc_and_free() -> Result<(), HardError> {
        unsafe {
            init()?;

            // Test allocations of various sizes
            let ptr_a: NonNull<u8> = malloc()?; // 1 byte
            let ptr_b: NonNull<[u8; 1 << 3]> = malloc()?; // 8 bytes
            let ptr_c: NonNull<[u8; 1 << 10]> = malloc()?; // 1 KiB
            let ptr_d: NonNull<[u8; 1 << 20]> = malloc()?; // 1 MiB

            // Free the allocated memory
            free(ptr_a);
            free(ptr_b);
            free(ptr_c);
            free(ptr_d);

            Ok(())
        }
    }

    #[test]
    fn memzero_does_zero() -> Result<(), HardError> {
        unsafe {
            init()?;

            let ptr_a: NonNull<u8> = malloc()?; // 1 byte
            let ptr_b: NonNull<[u8; 1 << 3]> = malloc()?; // 8 bytes
            let ptr_c: NonNull<[u8; 1 << 10]> = malloc()?; // 1 KiB
            let ptr_d: NonNull<[u8; 1 << 20]> = malloc()?; // 1 MiB

            memzero(ptr_a);
            memzero(ptr_b);
            memzero(ptr_c);
            memzero(ptr_d);

            // The value represented by all zeros for these array/integer types is well defined.
            assert_eq!(ptr_a.as_ref(), &0);
            assert_eq!(&ptr_b.as_ref()[..], &[0; 1 << 3][..]);
            assert_eq!(&ptr_c.as_ref()[..], &[0; 1 << 10][..]);
            assert_eq!(&ptr_d.as_ref()[..], &[0; 1 << 20][..]);

            free(ptr_a);
            free(ptr_b);
            free(ptr_c);
            free(ptr_d);

            Ok(())
        }
    }

    #[test]
    fn memcmp_compare_works() -> Result<(), HardError> {
        unsafe {
            init()?;

            let mut ptr_a: NonNull<[u8; 1 << 3]> = malloc()?;
            let mut ptr_b: NonNull<[u8; 1 << 3]> = malloc()?;

            ptr_a
                .as_mut()
                .copy_from_slice(&[0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe]);
            ptr_b
                .as_mut()
                .copy_from_slice(&[0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe]);
            assert!(memcmp(ptr_a, ptr_b));
            ptr_b
                .as_mut()
                .copy_from_slice(&[0xff, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe]);
            assert!(!memcmp(ptr_a, ptr_b));
            ptr_b
                .as_mut()
                .copy_from_slice(&[0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xff]);
            assert!(!memcmp(ptr_a, ptr_b));

            free(ptr_a);
            free(ptr_b);

            Ok(())
        }
    }

    #[test]
    fn mprotect_works() -> Result<(), HardError> {
        unsafe {
            init()?;

            let mut ptr: NonNull<[u8; 32]> = malloc()?;
            ptr.as_mut().copy_from_slice(&[0xfe; 32]);

            mprotect_noaccess(ptr)?;
            mprotect_readonly(ptr)?;
            assert_eq!(&ptr.as_ref()[..], &[0xfe; 32][..]);
            mprotect_readwrite(ptr)?;
            ptr.as_mut().copy_from_slice(&[0xba; 32]);
            assert_eq!(&ptr.as_ref()[..], &[0xba; 32][..]);

            free(ptr);

            Ok(())
        }
    }
}
