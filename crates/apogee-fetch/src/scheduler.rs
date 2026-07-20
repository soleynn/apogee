//! The job scheduler: bounded concurrency with priority admission.
//!
//! Two independent caps. A **job** admission gate bounds how many downloads run at once and, unlike a
//! FIFO semaphore, admits a waiting higher-priority job (a boot patch) ahead of a lower one (game
//! data, then optional assets) when a slot frees. A global **connection** semaphore bounds how many
//! sockets are open across every job at once. One [`Scheduler`] is shared by every clone of the
//! `Fetcher`, so the caps hold across concurrently submitted jobs.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use tokio::sync::{OwnedSemaphorePermit, Semaphore, oneshot};

/// A job's scheduling priority. Boot patches preempt game data, which preempts optional assets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum Priority {
    /// Boot patches: admitted ahead of everything.
    Boot,
    /// Game and expansion data: the default.
    #[default]
    Normal,
    /// Optional assets: yields to boot and game.
    Low,
}

/// The number of priority tiers, one waiter queue each.
const TIERS: usize = 3;

impl Priority {
    /// The waiter-queue index, highest priority first.
    fn rank(self) -> usize {
        match self {
            Priority::Boot => 0,
            Priority::Normal => 1,
            Priority::Low => 2,
        }
    }
}

/// The mutable admission state: free slots plus one waiter queue per priority tier.
#[derive(Debug)]
struct Admission {
    available: usize,
    tiers: [VecDeque<oneshot::Sender<()>>; TIERS],
}

/// Bounded, priority-aware concurrency for the fetcher.
#[derive(Debug)]
pub(crate) struct Scheduler {
    admission: Mutex<Admission>,
    connections: Arc<Semaphore>,
}

impl Scheduler {
    /// A scheduler admitting `max_files` jobs at once and `max_connections_total` sockets across them.
    pub(crate) fn new(max_files: usize, max_connections_total: usize) -> Self {
        Self {
            admission: Mutex::new(Admission {
                available: max_files.max(1),
                tiers: Default::default(),
            }),
            connections: Arc::new(Semaphore::new(max_connections_total.max(1))),
        }
    }

    /// Admit a job of `priority`, waiting for a slot if the gate is full. Higher-priority waiters are
    /// admitted first when a slot frees. The returned guard holds the slot until dropped.
    pub(crate) async fn acquire_job(self: &Arc<Self>, priority: Priority) -> AdmissionGuard {
        let waiter = {
            let mut a = self.lock();
            if a.available > 0 {
                a.available -= 1;
                None
            } else {
                let (tx, rx) = oneshot::channel();
                a.tiers[priority.rank()].push_back(tx);
                Some(rx)
            }
        };
        if let Some(rx) = waiter {
            // A slot is handed over by `release`; if the sender is somehow dropped, proceed rather
            // than hang (the count self-heals on the guard drop).
            let _ = rx.await;
        }
        AdmissionGuard {
            scheduler: Arc::clone(self),
        }
    }

    /// Take one global connection slot, waiting if all are in use. `None` only if the semaphore were
    /// closed (it never is), in which case the transfer proceeds uncounted rather than failing.
    pub(crate) async fn acquire_connection(&self) -> Option<OwnedSemaphorePermit> {
        Arc::clone(&self.connections).acquire_owned().await.ok()
    }

    /// Return a freed job slot to the highest-priority waiter, else to the free pool.
    fn release_job(&self) {
        let mut a = self.lock();
        for tier in &mut a.tiers {
            while let Some(tx) = tier.pop_front() {
                // A live receiver takes the slot directly (available stays put); a cancelled waiter
                // (dropped receiver) is skipped.
                if tx.send(()).is_ok() {
                    return;
                }
            }
        }
        a.available += 1;
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Admission> {
        self.admission
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// The number of jobs currently waiting for a slot (test-only observability).
    #[cfg(test)]
    fn waiting(&self) -> usize {
        self.lock().tiers.iter().map(VecDeque::len).sum()
    }
}

/// Holds one job admission slot; returns it to the scheduler on drop.
#[derive(Debug)]
pub(crate) struct AdmissionGuard {
    scheduler: Arc<Scheduler>,
}

impl Drop for AdmissionGuard {
    fn drop(&mut self) {
        self.scheduler.release_job();
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, Ordering::SeqCst};

    use super::*;

    #[tokio::test]
    async fn boot_preempts_normal_for_a_freed_slot() {
        let sched = Arc::new(Scheduler::new(1, 8));
        let held = sched.acquire_job(Priority::Normal).await; // takes the only slot

        let normal_in = Arc::new(AtomicBool::new(false));
        let boot_in = Arc::new(AtomicBool::new(false));
        // Enqueue Normal first, then Boot, to prove priority (not arrival order) decides. Each task
        // holds its slot forever so only one waiter can be admitted.
        let normal = tokio::spawn({
            let (s, flag) = (sched.clone(), normal_in.clone());
            async move {
                let _g = s.acquire_job(Priority::Normal).await;
                flag.store(true, SeqCst);
                std::future::pending::<()>().await;
            }
        });
        let boot = tokio::spawn({
            let (s, flag) = (sched.clone(), boot_in.clone());
            async move {
                let _g = s.acquire_job(Priority::Boot).await;
                flag.store(true, SeqCst);
                std::future::pending::<()>().await;
            }
        });
        while sched.waiting() < 2 {
            tokio::task::yield_now().await;
        }

        drop(held); // frees the single slot
        while !boot_in.load(SeqCst) {
            tokio::task::yield_now().await;
        }
        assert!(
            !normal_in.load(SeqCst),
            "the freed slot must go to the waiting boot job, not the earlier normal one",
        );

        normal.abort();
        boot.abort();
    }

    #[tokio::test]
    async fn a_freed_slot_with_no_waiters_returns_to_the_pool() {
        let sched = Arc::new(Scheduler::new(1, 8));
        let g = sched.acquire_job(Priority::Normal).await;
        drop(g);
        // The slot is free again, so a fresh acquire proceeds without waiting.
        let _g2 = sched.acquire_job(Priority::Boot).await;
        assert_eq!(sched.waiting(), 0);
    }

    #[tokio::test]
    async fn connection_permits_bound_concurrency() {
        let sched = Scheduler::new(4, 1);
        let first = sched.acquire_connection().await;
        assert!(first.is_some());
        // The single connection slot is taken; a second acquire cannot resolve yet.
        let pending =
            tokio::time::timeout(std::time::Duration::from_millis(20), sched.acquire_connection())
                .await;
        assert!(pending.is_err(), "a second connection must wait for the first to release");
        drop(first);
        assert!(sched.acquire_connection().await.is_some());
    }
}
