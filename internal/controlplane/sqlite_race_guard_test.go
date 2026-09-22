package controlplane

import (
	"database/sql"
	"fmt"
	"os"
	"testing"

	_ "modernc.org/sqlite"
)

// TestMain serializes the modernc.org/sqlite driver's lazy global mutex-pool
// initialization BEFORE any parallel test opens a database, then runs the
// suite. It does NOT disable the race detector, skip tests, or reduce
// parallelism — it only pre-grows the driver's process-global mutex pool under
// single-threaded control so that the pool's backing slice (modernc
// sqlite/lib mutex.go: m.a) is never re-allocated (appended) while concurrent
// tests read it.
//
// Why this is needed: modernc's mutexPool starts with one 256-mutex block.
// alloc() only appends a new block when the free list runs dry — and that
// append (mutex.go:107 `m.a = append(...)`) WRITES the shared slice header,
// while mutexFromPtr() (mutex.go:96 `&mutexes.a[ix>>8][ix&255]`) READS it
// WITHOUT holding the pool lock. When enough in-memory test databases first
// open concurrently (parallel controlplane tests), the pool grows past its
// initial 256 slots at the same moment another goroutine translates a mutex
// pointer, and the race detector reports mutexPool.alloc vs mutexFromPtr.
// Captured intermittently in the full suite; deterministic under our own
// reproduction (opening many shared-memory connections at once).
//
// The guard forces that one-time growth to happen here, serially, before any
// test starts. Because m.a NEVER shrinks (free() only returns indices to the
// free list; alloc() only appends), the pre-grown capacity persists for the
// rest of the process: after this warm-up, alloc() finds free slots and never
// triggers the append, so no test-initiated pool write can race a reader.
// Production startup is unaffected: this is test-only file initialisation for
// the controlplane package, and each real database uses a handful of mutexes
// well within the initial pool.
func TestMain(m *testing.M) {
	primeSQLiteMutexPool()
	os.Exit(m.Run())
}

// primeSQLiteMutexPool forces the modernc sqlite mutex pool to grow to a
// capacity far beyond what the parallel controlplane suite will ever hold
// concurrently, while serialized. It opens and immediately PINGs enough
// distinct in-memory databases so that at least sqliteMutexPoolPrimeSlots
// mutexes are allocated and held at once (the pool then has capacity for that
// many). All are closed before the tests run; the grown backing capacity
// persists regardless. The count is oversized relative to the suite's true
// peak (a few hundred at GOMAXPROCS=8) so the pool never needs to append
// during tests.
func primeSQLiteMutexPool() {
	held := make([]*sql.DB, 0, sqliteMutexPoolPrimeSlots)
	for i := 0; i < sqliteMutexPoolPrimeSlots; i++ {
		db, err := sql.Open("sqlite", fmt.Sprintf("file:prime_%d?mode=memory&cache=shared", i))
		if err != nil {
			continue
		}
		if err := db.Ping(); err != nil {
			_ = db.Close()
			continue
		}
		held = append(held, db)
	}
	for _, db := range held {
		_ = db.Close()
	}
}

// sqliteMutexPoolPrimeSlots is the number of simultaneously-held in-memory
// connections used to pre-grow modernc's mutex pool. Each opens within its own
// shared-memory database; the pool's per-connection mutex allocation holds a
// small constant number of slots. 4096 gives the driver ~16+ blocks of
// capacity — comfortably above the suite's real concurrent peak (tens of
// databases across GOMAXPROCS, each a handful of mutexes) yet fast (~80ms).
const sqliteMutexPoolPrimeSlots = 4096
