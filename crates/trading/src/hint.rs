//! Cache hints for the `apply_batch` look-ahead pipeline.
//!
//! A hint reads possibly-stale state through a shared reference and
//! never writes, so it can change timing but never behaviour.
//!
//! * Cargo feature `prefetch` (off by default): a real software
//!   prefetch (`prfm pldl1keep` on `aarch64`, `prefetcht0` on `x86_64`).
//!   This is the crate's only `unsafe`: one audited helper below,
//!   under the workspace's reviewed-exception rule
//!   (`#[allow(unsafe_code)]` + SAFETY comment).
//! * Default: a plain load fed to `black_box`. The out-of-order core
//!   overlaps the miss with the commands ahead, but the load occupies
//!   a reorder-buffer entry until it returns, so on deep books it
//!   buys much less than a true prefetch (measured: see devlog).

/// Hint that `*r`'s cache line is about to be read.
#[allow(clippy::inline_always)] // a hint must not become a call
#[inline(always)]
pub fn prefetch<T: Copy>(r: &T) {
    imp::hint(r);
}

#[cfg(not(feature = "prefetch"))]
mod imp {
    #[allow(clippy::inline_always)]
    #[inline(always)]
    pub fn hint<T: Copy>(r: &T) {
        std::hint::black_box(*r);
    }
}

#[cfg(feature = "prefetch")]
mod imp {
    /// Software prefetch of the line holding `*r`.
    ///
    /// SAFETY: a prefetch is an architectural no-op hint — it never
    /// faults (even on an invalid address), never writes, and has no
    /// effect on program state. `r` is additionally a live shared
    /// reference, so the address is valid regardless.
    #[allow(unsafe_code, clippy::inline_always)]
    #[inline(always)]
    pub fn hint<T: Copy>(r: &T) {
        let p = std::ptr::from_ref(r);
        #[cfg(target_arch = "aarch64")]
        unsafe {
            std::arch::asm!(
                "prfm pldl1keep, [{0}]",
                in(reg) p,
                options(nostack, preserves_flags, readonly)
            );
        }
        #[cfg(target_arch = "x86_64")]
        unsafe {
            use std::arch::x86_64::{_MM_HINT_T0, _mm_prefetch};
            _mm_prefetch::<_MM_HINT_T0>(p.cast::<i8>());
        }
        #[cfg(not(any(target_arch = "aarch64", target_arch = "x86_64")))]
        {
            let _ = p;
        }
    }
}
