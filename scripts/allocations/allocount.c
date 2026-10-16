// Counts glibc allocator calls in a process and reports them on exit.
//
// Interposes the four entry points Rust's `std::alloc::System` uses on Unix and
// forwards to glibc's own symbols, which avoids the dlsym-during-init recursion a
// RTLD_NEXT lookup would risk. Counters are relaxed: the report is a total, and no
// reader observes them before exit.
//
// With LORE_ALLOC_HISTOGRAM_FILE set, it also counts requests by size and writes
// "<size> <count>" lines to that file on exit, requests of 1 MiB and more as one
// "large <count> <bytes>" line.
#define _GNU_SOURCE
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

extern void *__libc_malloc(size_t);
extern void *__libc_calloc(size_t, size_t);
extern void *__libc_realloc(void *, size_t);
extern void __libc_free(void *);

static atomic_ullong n_malloc, n_calloc, n_realloc, n_free, n_memalign;

#define EXACT_SIZES (1u << 20)
static int by_size_enabled;
static atomic_ullong by_size[EXACT_SIZES];
static atomic_ullong large_count, large_bytes;

static void count_size(size_t size) {
    if (!by_size_enabled) return;
    if (size < EXACT_SIZES) {
        atomic_fetch_add_explicit(&by_size[size], 1, memory_order_relaxed);
    } else {
        atomic_fetch_add_explicit(&large_count, 1, memory_order_relaxed);
        atomic_fetch_add_explicit(&large_bytes, size, memory_order_relaxed);
    }
}

void *malloc(size_t size) {
    atomic_fetch_add_explicit(&n_malloc, 1, memory_order_relaxed);
    count_size(size);
    return __libc_malloc(size);
}

void *calloc(size_t count, size_t size) {
    atomic_fetch_add_explicit(&n_calloc, 1, memory_order_relaxed);
    count_size(count * size);
    return __libc_calloc(count, size);
}

void *realloc(void *ptr, size_t size) {
    atomic_fetch_add_explicit(&n_realloc, 1, memory_order_relaxed);
    count_size(size);
    return __libc_realloc(ptr, size);
}

void free(void *ptr) {
    if (ptr) atomic_fetch_add_explicit(&n_free, 1, memory_order_relaxed);
    __libc_free(ptr);
}

int posix_memalign(void **out, size_t align, size_t size) {
    atomic_fetch_add_explicit(&n_memalign, 1, memory_order_relaxed);
    count_size(size);
    // glibc has no __libc_posix_memalign; over-aligned blocks are rare here and
    // aligned_alloc is not interposed, so it reaches the real allocator.
    void *p = aligned_alloc(align, size);
    if (!p) return 12;
    *out = p;
    return 0;
}

// The running total, for a caller scoping a measurement to one phase of its own run.
unsigned long long allocount_total(void) {
    return atomic_load_explicit(&n_malloc, memory_order_relaxed)
         + atomic_load_explicit(&n_calloc, memory_order_relaxed)
         + atomic_load_explicit(&n_realloc, memory_order_relaxed)
         + atomic_load_explicit(&n_memalign, memory_order_relaxed);
}

static void report_by_size(void) {
    const char *path = getenv("LORE_ALLOC_HISTOGRAM_FILE");
    if (!by_size_enabled || !path) return;
    FILE *out = fopen(path, "w");
    if (!out) return;
    for (size_t size = 0; size < EXACT_SIZES; size++) {
        unsigned long long count = atomic_load_explicit(&by_size[size], memory_order_relaxed);
        if (count) fprintf(out, "%zu %llu\n", size, count);
    }
    if (atomic_load(&large_count)) fprintf(out, "large %llu %llu\n", atomic_load(&large_count), atomic_load(&large_bytes));
    fclose(out);
}

__attribute__((destructor)) static void report(void) {
    const char *path = getenv("LORE_ALLOC_COUNT_FILE");
    FILE *out = path ? fopen(path, "a") : stderr;
    if (!out) return;
    fprintf(out, "allocount pid=%d malloc=%llu calloc=%llu realloc=%llu memalign=%llu free=%llu total=%llu\n",
            (int)getpid(),
            atomic_load(&n_malloc), atomic_load(&n_calloc), atomic_load(&n_realloc),
            atomic_load(&n_memalign), atomic_load(&n_free),
            atomic_load(&n_malloc) + atomic_load(&n_calloc) + atomic_load(&n_realloc) + atomic_load(&n_memalign));
    if (path) fclose(out);
    report_by_size();
}

__attribute__((constructor)) static void announce(void) {
    by_size_enabled = getenv("LORE_ALLOC_HISTOGRAM_FILE") != NULL;
    if (getenv("LORE_ALLOC_COUNT_DEBUG")) fprintf(stderr, "allocount loaded pid=%d\n", (int)getpid());
}
