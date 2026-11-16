//! Limit pamięci procesu. Biblioteki IronRDP składają fragmenty kanałów statycznych i dynamicznych
//! bez górnej granicy, więc złośliwy serwer mógłby dowolnie zwiększać pamięć procesu. Globalny
//! alokator liczy bieżącą sumę przydzielonych bajtów: po przekroczeniu progu twardego alokacja
//! zwraca null (proces kończy się standardową ścieżką błędu alokacji), a próg miękki sprawdza
//! pętla główna (`check_soft`), żeby zakończyć sesję czytelnym błędem. To jedyny moduł z `unsafe`
//! (wymaga go `GlobalAlloc`).

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};

/// Twardy próg: powyżej niego alokacja się nie udaje.
pub const HARD_LIMIT: usize = 2 << 30;
/// Miękki próg: powyżej niego pętla główna kończy sesję błędem.
pub const SOFT_LIMIT: usize = 1536 << 20;

/// Czy do bieżącej sumy `current` można dołożyć `request` bajtów bez przekroczenia `limit`.
pub fn admit(current: usize, request: usize, limit: usize) -> bool {
    current.checked_add(request).is_some_and(|t| t <= limit)
}

/// Alokator zliczający bajty nad alokatorem `A`.
pub struct Counting<A> {
    inner: A,
    used: AtomicUsize,
    limit: usize,
}

impl<A> Counting<A> {
    pub const fn new(inner: A, limit: usize) -> Self {
        Self {
            inner,
            used: AtomicUsize::new(0),
            limit,
        }
    }

    /// Bieżąca suma przydzielonych bajtów.
    pub fn used(&self) -> usize {
        self.used.load(Ordering::Relaxed)
    }

    /// Rezerwuje `n` bajtów w liczniku; false, gdy przekroczyłoby to twardy próg.
    fn reserve(&self, n: usize) -> bool {
        self.used
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |cur| {
                admit(cur, n, self.limit).then_some(cur + n)
            })
            .is_ok()
    }

    fn release(&self, n: usize) {
        self.used.fetch_sub(n, Ordering::Relaxed);
    }
}

// SAFETY: każda metoda deleguje do `A` z niezmienionym układem pamięci, a licznik nie wpływa na
// poprawność zwracanych bloków; przy odmowie zwracany jest null, co `GlobalAlloc` dopuszcza.
unsafe impl<A: GlobalAlloc> GlobalAlloc for Counting<A> {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if !self.reserve(layout.size()) {
            return std::ptr::null_mut();
        }
        // SAFETY: `layout` pochodzi od wywołującego i spełnia kontrakt `GlobalAlloc::alloc`.
        let p = unsafe { self.inner.alloc(layout) };
        if p.is_null() {
            self.release(layout.size());
        }
        p
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        if !self.reserve(layout.size()) {
            return std::ptr::null_mut();
        }
        // SAFETY: `layout` pochodzi od wywołującego i spełnia kontrakt `alloc_zeroed`.
        let p = unsafe { self.inner.alloc_zeroed(layout) };
        if p.is_null() {
            self.release(layout.size());
        }
        p
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: `ptr` i `layout` pochodzą z wcześniejszej alokacji tego alokatora (kontrakt `dealloc`).
        unsafe { self.inner.dealloc(ptr, layout) };
        self.release(layout.size());
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let old = layout.size();
        if new_size > old && !self.reserve(new_size - old) {
            return std::ptr::null_mut();
        }
        // SAFETY: `ptr` i `layout` pochodzą z tego alokatora, a `new_size` spełnia kontrakt `realloc`.
        let p = unsafe { self.inner.realloc(ptr, layout, new_size) };
        if p.is_null() {
            // Stary blok pozostaje ważny, więc cofamy tylko rezerwację dodatkowych bajtów.
            if new_size > old {
                self.release(new_size - old);
            }
        } else if new_size < old {
            self.release(old - new_size);
        }
        p
    }
}

#[global_allocator]
static ALLOC: Counting<System> = Counting::new(System, HARD_LIMIT);

/// Błąd, gdy proces przekroczył miękki próg pamięci (sprawdzane w pętli głównej).
pub fn check_soft() -> anyhow::Result<()> {
    soft_check(ALLOC.used(), SOFT_LIMIT)
}

fn soft_check(used: usize, soft: usize) -> anyhow::Result<()> {
    if used > soft {
        anyhow::bail!(
            "proces RDP zużył za dużo pamięci ({} MiB), sesja zakończona: serwer przysyła nadmiar danych",
            used >> 20
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn admit_decides_on_sum_and_limit() {
        assert!(admit(0, 100, 100));
        assert!(!admit(1, 100, 100));
        assert!(admit(40, 60, 100));
        assert!(!admit(usize::MAX, 1, usize::MAX));
        assert!(!admit(10, usize::MAX, usize::MAX));
    }

    #[test]
    fn soft_threshold_is_below_hard_and_reports_in_polish() {
        const { assert!(SOFT_LIMIT < HARD_LIMIT) };
        assert!(soft_check(SOFT_LIMIT, SOFT_LIMIT).is_ok());
        let e = soft_check(SOFT_LIMIT + 1, SOFT_LIMIT).unwrap_err();
        assert!(e.to_string().contains("za dużo pamięci"));
    }

    #[test]
    fn counter_tracks_alloc_zeroed_realloc_and_dealloc() {
        let a = Counting::new(System, 1000);
        let l = |n| Layout::from_size_align(n, 8).unwrap();
        // SAFETY: układy są poprawne, a każdy wskaźnik jest zwalniany z układem o aktualnym rozmiarze.
        unsafe {
            let p = a.alloc(l(100));
            assert!(!p.is_null());
            assert_eq!(a.used(), 100);
            let p = a.realloc(p, l(100), 400);
            assert!(!p.is_null());
            assert_eq!(a.used(), 400);
            let p = a.realloc(p, l(400), 50);
            assert!(!p.is_null());
            assert_eq!(a.used(), 50);
            let z = a.alloc_zeroed(l(200));
            assert!(!z.is_null());
            assert_eq!(*z, 0);
            assert_eq!(a.used(), 250);
            a.dealloc(p, l(50));
            a.dealloc(z, l(200));
        }
        assert_eq!(a.used(), 0);
    }

    #[test]
    fn hard_limit_returns_null_without_changing_counter() {
        let a = Counting::new(System, 1000);
        let l = |n| Layout::from_size_align(n, 8).unwrap();
        // SAFETY: układy są poprawne; nieudane wywołania nie zwracają pamięci do zwolnienia.
        unsafe {
            let p = a.alloc(l(600));
            assert!(!p.is_null());
            assert!(a.alloc(l(500)).is_null());
            assert!(a.alloc_zeroed(l(500)).is_null());
            assert!(a.realloc(p, l(600), 1001).is_null());
            assert_eq!(a.used(), 600);
            a.dealloc(p, l(600));
        }
        assert_eq!(a.used(), 0);
    }
}
