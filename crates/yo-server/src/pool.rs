//! A small pool of SQLite connections used from blocking threads, so slow
//! queries never stall the async runtime (SECURITY_REVIEW.md, L-2).
//!
//! SQLite in WAL mode lets several readers run alongside one writer; the
//! busy timeout set in `Db::open` makes writers queue instead of failing.

use std::path::Path;
use std::sync::{Arc, Mutex};

use tokio::sync::Semaphore;

use crate::db::Db;

pub struct DbPool {
    inner: Arc<Inner>,
}

struct Inner {
    conns: Mutex<Vec<Db>>,
    free: Semaphore,
}

impl DbPool {
    /// Open `size` connections to the database at `path`.
    pub fn open(path: &Path, size: usize) -> rusqlite::Result<DbPool> {
        let size = size.max(1);
        let mut conns = Vec::with_capacity(size);
        for _ in 0..size {
            conns.push(Db::open(path)?);
        }
        Ok(DbPool { inner: Arc::new(Inner { conns: Mutex::new(conns), free: Semaphore::new(size) }) })
    }

    /// Run `f` with a connection on a blocking thread.
    pub async fn run<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&mut Db) -> R + Send + 'static,
        R: Send + 'static,
    {
        let inner = self.inner.clone();
        let permit = inner.free.acquire().await.expect("pool semaphore is never closed");
        let mut db = inner.conns.lock().expect("pool lock").pop().expect("a permit guarantees a connection");
        let inner2 = inner.clone();
        let result = tokio::task::spawn_blocking(move || {
            let r = f(&mut db);
            inner2.conns.lock().expect("pool lock").push(db);
            r
        })
        .await;
        drop(permit);
        result.expect("database task panicked")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn queries_run_in_parallel_off_the_runtime() {
        let dir = tempfile::tempdir().unwrap();
        let pool = Arc::new(DbPool::open(&dir.path().join("p.db"), 4).unwrap());
        let start = Instant::now();
        let mut tasks = Vec::new();
        for _ in 0..8 {
            let p = pool.clone();
            tasks.push(tokio::spawn(async move {
                p.run(|db| {
                    std::thread::sleep(Duration::from_millis(100));
                    db.stats().unwrap();
                })
                .await
            }));
        }
        // Meanwhile the runtime stays responsive.
        let ping = Instant::now();
        tokio::time::sleep(Duration::from_millis(10)).await;
        assert!(ping.elapsed() < Duration::from_millis(80), "runtime was blocked");
        for t in tasks {
            t.await.unwrap();
        }
        // 8 × 100 ms of blocking work on 4 connections ≈ 200 ms, not 800 ms.
        assert!(start.elapsed() < Duration::from_millis(600), "took {:?}", start.elapsed());
    }
}
