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
    ///
    /// A freed slot is returned to the pool (never handed directly to a waiter), and a woken waiter
    /// re-checks it under the lock, so a waiter whose future is cancelled cannot lose the slot.
    pub(crate) async fn acquire_job(self: &Arc<Self>, priority: Priority) -> AdmissionGuard {
        loop {
            let rx = {
                let mut a = self.lock();
                if a.available > 0 {
                    a.available -= 1;
                    return AdmissionGuard {
                        scheduler: Arc::clone(self),
                    };
                }
                let (tx, rx) = oneshot::channel();
                a.tiers[priority.rank()].push_back(tx);
                rx
            };
            // If this future is cancelled while parked, pass our wakeup on so a freed slot is not
            // swallowed; a normal wakeup disarms the poke and loops to claim the slot itself.
            let mut poke = PokeOnDrop(Some(Arc::clone(self)));
            let _ = rx.await;
            poke.0 = None;
        }
    }

    /// Take one global connection slot, waiting if all are in use. `None` only if the semaphore were
    /// closed (it never is), in which case the transfer proceeds uncounted rather than failing.
    pub(crate) async fn acquire_connection(&self) -> Option<OwnedSemaphorePermit> {
        Arc::clone(&self.connections).acquire_owned().await.ok()
    }

    /// Return a freed slot to the pool and wake the highest-priority live waiter to claim it. The slot
    /// is counted in `available` first, so a woken waiter that is then cancelled cannot lose it.
    fn release_job(&self) {
        let mut a = self.lock();
        a.available += 1;
        wake_next(&mut a.tiers);
    }

    /// Wake a live waiter if a slot is free, so a cancelled acquire that consumed a wakeup does not
    /// leave a peer parked next to an idle slot.
    fn wake_one(&self) {
        let mut a = self.lock();
        if a.available > 0 {
            wake_next(&mut a.tiers);
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Admission> {
        crate::util::lock(&self.admission)
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

/// Wake the highest-priority live waiter, skipping cancelled ones (whose receiver has been dropped).
fn wake_next(tiers: &mut [VecDeque<oneshot::Sender<()>>]) {
    for tier in tiers {
        while let Some(tx) = tier.pop_front() {
            if tx.send(()).is_ok() {
                return;
            }
        }
    }
}

/// Held by a parked `acquire_job`. If that future is dropped while waiting (a cancelled acquire), it
/// wakes another waiter so a freed slot the drop might have consumed is not left stranded. Disarmed
/// (`None`) on a normal wakeup, where the waiter loops to claim the slot itself.
struct PokeOnDrop(Option<Arc<Scheduler>>);

impl Drop for PokeOnDrop {
    fn drop(&mut self) {
        if let Some(scheduler) = self.0.take() {
            scheduler.wake_one();
        }
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

    #[test]
    fn a_released_slot_survives_a_waiter_that_never_claims() {
        // Reproduces the slot-leak race deterministically: a freed slot must land in the pool, not be
        // handed to a waiter that is then cancelled before building a guard.
        let sched = Arc::new(Scheduler::new(1, 8));
        // Take the only slot, then park a live waiter (its receiver still alive).
        let rx = {
            let mut a = sched.lock();
            a.available = 0;
            let (tx, rx) = oneshot::channel();
            a.tiers[Priority::Normal.rank()].push_back(tx);
            rx
        };
        sched.release_job();
        // The waiter received its wakeup but is cancelled before claiming (its future is dropped).
        drop(rx);
        assert_eq!(
            sched.lock().available,
            1,
            "a freed slot must return to the pool, not vanish with a cancelled waiter",
        );
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
        let pending = tokio::time::timeout(
            std::time::Duration::from_millis(20),
            sched.acquire_connection(),
        )
        .await;
        assert!(
            pending.is_err(),
            "a second connection must wait for the first to release"
        );
        drop(first);
        assert!(sched.acquire_connection().await.is_some());
    }
}
