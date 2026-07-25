//! Frame-consistency metrics over one run's per-frame frametimes.
//!
//! The default-runner sweep records a frametime log per run; this module turns the raw per-frame
//! frametimes into the figures the matrix ranks on: time-weighted average FPS, the 1% and 0.1%
//! lows, and the frametime spread. Pure and host-free. The log decode that feeds it is a separate
//! concern; a [`BenchStats`] is computed from frametimes already in milliseconds.

use std::collections::BTreeMap;

use serde::Serialize;
use thiserror::Error;

/// Why frametime statistics could not be computed.
#[derive(Debug, Error, Clone, PartialEq)]
#[non_exhaustive]
pub enum BenchError {
    /// The run carried no frames to measure.
    #[error("no frames in the run")]
    NoFrames,
    /// A frametime was zero, negative, or non-finite, so FPS is undefined.
    #[error("frametime #{index} is not a positive finite value ({value})")]
    BadFrametime { index: usize, value: f64 },
    /// No MangoHud data header (a line beginning `fps,frametime,...`) was found in the log.
    #[error("no MangoHud data header found")]
    NoDataHeader,
    /// A column the parser needs is absent from the log's data header.
    #[error("required column {name} is missing from the log header")]
    MissingColumn { name: &'static str },
    /// A data row could not be read (short row or an unparseable frametime cell).
    #[error("line {line}: {reason}")]
    MalformedRow { line: usize, reason: &'static str },
}

/// Frame-consistency metrics for one run (see [`BenchStats::from_frametimes`]).
///
/// FPS figures are time-weighted (frames over elapsed time), so `average_fps` equals
/// `1000 / frametime_mean_ms`. The lows are the mean FPS across the slowest tail of frames:
/// `low_1pct` over the slowest 1%, `low_0_1pct` over the slowest 0.1% (tail size rounds up, minimum
/// one frame). `frametime_stddev_ms` is the population standard deviation of the frametimes, the
/// headline consistency figure.
#[derive(Debug, Clone, Copy, PartialEq, Serialize)]
pub struct BenchStats {
    /// Number of frames in the run.
    pub frame_count: usize,
    /// Wall-clock length of the run, in seconds (sum of frametimes).
    pub duration_s: f64,
    /// Time-weighted average FPS over the whole run.
    pub average_fps: f64,
    /// Mean FPS across the slowest 1% of frames.
    pub low_1pct: f64,
    /// Mean FPS across the slowest 0.1% of frames.
    pub low_0_1pct: f64,
    /// Mean frametime, in milliseconds.
    pub frametime_mean_ms: f64,
    /// Population standard deviation of the frametimes, in milliseconds.
    pub frametime_stddev_ms: f64,
}

impl BenchStats {
    /// Compute the metrics from a run's per-frame frametimes, given in milliseconds and capture
    /// order. Ordering does not affect the result.
    ///
    /// # Errors
    /// [`BenchError::NoFrames`] if `frametimes_ms` is empty, or [`BenchError::BadFrametime`] if any
    /// entry is not a positive finite number (FPS would be undefined).
    pub fn from_frametimes(frametimes_ms: &[f64]) -> Result<Self, BenchError> {
        if frametimes_ms.is_empty() {
            return Err(BenchError::NoFrames);
        }
        for (index, &value) in frametimes_ms.iter().enumerate() {
            if !value.is_finite() || value <= 0.0 {
                return Err(BenchError::BadFrametime { index, value });
            }
        }

        let n = frametimes_ms.len();
        let total_ms: f64 = frametimes_ms.iter().sum();
        let frametime_mean_ms = total_ms / n as f64;

        let variance = frametimes_ms
            .iter()
            .map(|&ft| {
                let d = ft - frametime_mean_ms;
                d * d
            })
            .sum::<f64>()
            / n as f64;

        // Sort ascending so the slowest frames (largest frametimes) sit at the tail. `total_cmp`
        // gives a total order without a partial-compare panic path; every entry is finite here.
        let mut sorted = frametimes_ms.to_vec();
        sorted.sort_by(f64::total_cmp);

        Ok(Self {
            frame_count: n,
            duration_s: total_ms / 1000.0,
            average_fps: 1000.0 / frametime_mean_ms,
            low_1pct: slowest_tail_fps(&sorted, 0.01),
            low_0_1pct: slowest_tail_fps(&sorted, 0.001),
            frametime_mean_ms,
            frametime_stddev_ms: variance.sqrt(),
        })
    }
}

/// Mean FPS across the slowest `fraction` of frames. `sorted_ascending` holds the frametimes in
/// ascending order, so the slowest frames are the tail. The tail size rounds up and is at least one
/// frame, so even a short run yields a figure.
fn slowest_tail_fps(sorted_ascending: &[f64], fraction: f64) -> f64 {
    let n = sorted_ascending.len();
    let count = ((n as f64) * fraction).ceil() as usize;
    let count = count.clamp(1, n);
    let tail = &sorted_ascending[n - count..];
    let tail_mean_ms = tail.iter().sum::<f64>() / count as f64;
    1000.0 / tail_mean_ms
}

/// A parsed MangoHud frametime log: the capture machine's metadata block and the per-frame
/// frametimes.
///
/// MangoHud writes a CSV whose leading lines carry the machine (`os,cpu,gpu,...` keys, then their
/// values), followed by a data header beginning `fps,frametime,...` and one row per frame. Only the
/// `frametime` column (milliseconds) is required; the rest is provenance.
#[derive(Debug, Clone, PartialEq)]
pub struct FrameLog {
    /// The capture machine, keyed by MangoHud's metadata column names (`os`, `cpu`, `gpu`, ...).
    pub metadata: BTreeMap<String, String>,
    /// Per-frame frametimes in milliseconds, in capture order.
    pub frametimes_ms: Vec<f64>,
    /// Rows dropped as instrumentation artifacts: a frametime longer than the process's uptime at
    /// the moment it was logged (the `elapsed` column) is not a frame. Some MangoHud builds write
    /// one such garbage row first, having no prior frame to diff against.
    pub artifacts_dropped: usize,
}

impl FrameLog {
    /// Parse a MangoHud frametime-log CSV. The metadata block is optional; the `fps,frametime,...`
    /// data header and a `frametime` column are required. Rows whose frametime exceeds the
    /// process's uptime at log time (the `elapsed` column) are dropped as instrumentation
    /// artifacts and counted in [`FrameLog::artifacts_dropped`].
    ///
    /// # Errors
    /// [`BenchError::NoDataHeader`], [`BenchError::MissingColumn`], or [`BenchError::MalformedRow`]
    /// for a header-less, column-less, or unparseable log.
    pub fn from_mangohud_csv(text: &str) -> Result<Self, BenchError> {
        let lines: Vec<&str> = text.lines().collect();
        let header_idx = lines
            .iter()
            .position(|l| {
                let mut cols = l.split(',');
                cols.next() == Some("fps") && l.split(',').any(|c| c == "frametime")
            })
            .ok_or(BenchError::NoDataHeader)?;

        let header: Vec<&str> = lines[header_idx].split(',').map(str::trim).collect();
        let ft = header
            .iter()
            .position(|c| *c == "frametime")
            .ok_or(BenchError::MissingColumn { name: "frametime" })?;
        // Uptime at log time, in nanoseconds; used to reject impossible frametimes. Optional.
        let elapsed = header.iter().position(|c| *c == "elapsed");

        // The two lines before the header, when present, are MangoHud's metadata keys and values.
        let mut metadata = BTreeMap::new();
        if header_idx >= 2 {
            let values: Vec<&str> = lines[header_idx - 1].split(',').collect();
            for (i, key) in lines[header_idx - 2].split(',').enumerate() {
                if let Some(value) = values.get(i) {
                    metadata.insert(key.trim().to_owned(), value.trim().to_owned());
                }
            }
        }

        let mut frametimes_ms = Vec::new();
        let mut artifacts_dropped = 0;
        for (offset, line) in lines[header_idx + 1..].iter().enumerate() {
            if line.trim().is_empty() {
                continue;
            }
            let line_no = header_idx + 2 + offset;
            let cells: Vec<&str> = line.split(',').collect();
            let cell = cells.get(ft).ok_or(BenchError::MalformedRow {
                line: line_no,
                reason: "missing frametime column",
            })?;
            let value: f64 = cell.trim().parse().map_err(|_| BenchError::MalformedRow {
                line: line_no,
                reason: "frametime is not a number",
            })?;
            // A frame cannot be longer than the process's uptime when it was logged; such a row is
            // an instrumentation artifact (some MangoHud builds write one as the first sample).
            if let Some(uptime_ms) = elapsed
                .and_then(|i| cells.get(i))
                .and_then(|c| c.trim().parse::<f64>().ok())
                .map(|ns| ns / 1e6)
                && value > uptime_ms
            {
                artifacts_dropped += 1;
                continue;
            }
            frametimes_ms.push(value);
        }

        Ok(Self {
            metadata,
            frametimes_ms,
            artifacts_dropped,
        })
    }

    /// Compute the frame-consistency metrics for this log.
    ///
    /// # Errors
    /// Propagates [`BenchStats::from_frametimes`].
    pub fn stats(&self) -> Result<BenchStats, BenchError> {
        BenchStats::from_frametimes(&self.frametimes_ms)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Assert two FPS/ms figures agree to floating-point tolerance.
    fn close(a: f64, b: f64) {
        assert!((a - b).abs() < 1e-9, "{a} != {b}");
    }

    #[test]
    fn steady_sixty_is_flat() {
        let frame = 1000.0 / 60.0;
        let frames = vec![frame; 600];
        let stats = BenchStats::from_frametimes(&frames).unwrap();

        assert_eq!(stats.frame_count, 600);
        close(stats.average_fps, 60.0);
        close(stats.low_1pct, 60.0);
        close(stats.low_0_1pct, 60.0);
        close(stats.frametime_mean_ms, frame);
        close(stats.frametime_stddev_ms, 0.0);
        close(stats.duration_s, 10.0);
    }

    #[test]
    fn a_slow_tail_pulls_the_lows_down_not_the_average() {
        // 990 fast frames (10 ms) and 10 stutters (100 ms): the slowest 1% is exactly the stutters.
        let mut frames = vec![10.0; 990];
        frames.extend(std::iter::repeat_n(100.0, 10));
        let stats = BenchStats::from_frametimes(&frames).unwrap();

        // Mean frametime 10.9 ms over 1000 frames -> ~91.7 average FPS.
        close(stats.frametime_mean_ms, 10.9);
        close(stats.average_fps, 1000.0 / 10.9);
        // Slowest 1% = 10 frames at 100 ms -> 10 FPS; 0.1% = 1 frame at 100 ms -> 10 FPS.
        close(stats.low_1pct, 10.0);
        close(stats.low_0_1pct, 10.0);
    }

    #[test]
    fn capture_order_does_not_matter() {
        let ascending = vec![8.0, 9.0, 10.0, 40.0, 50.0];
        let mut shuffled = vec![50.0, 8.0, 40.0, 10.0, 9.0];
        let a = BenchStats::from_frametimes(&ascending).unwrap();
        let b = BenchStats::from_frametimes(&shuffled).unwrap();
        assert_eq!(a, b);
        shuffled.reverse();
        assert_eq!(a, BenchStats::from_frametimes(&shuffled).unwrap());
    }

    #[test]
    fn a_single_frame_has_no_spread_and_equal_lows() {
        let stats = BenchStats::from_frametimes(&[20.0]).unwrap();
        assert_eq!(stats.frame_count, 1);
        close(stats.average_fps, 50.0);
        close(stats.low_1pct, 50.0);
        close(stats.low_0_1pct, 50.0);
        close(stats.frametime_stddev_ms, 0.0);
    }

    #[test]
    fn empty_run_is_rejected() {
        assert_eq!(BenchStats::from_frametimes(&[]), Err(BenchError::NoFrames));
    }

    #[test]
    fn non_positive_and_non_finite_frametimes_are_rejected() {
        assert_eq!(
            BenchStats::from_frametimes(&[16.0, 0.0, 16.0]),
            Err(BenchError::BadFrametime {
                index: 1,
                value: 0.0
            }),
        );
        assert_eq!(
            BenchStats::from_frametimes(&[16.0, -1.0]),
            Err(BenchError::BadFrametime {
                index: 1,
                value: -1.0
            }),
        );
        assert!(matches!(
            BenchStats::from_frametimes(&[f64::NAN]),
            Err(BenchError::BadFrametime { index: 0, .. }),
        ));
        assert!(matches!(
            BenchStats::from_frametimes(&[f64::INFINITY]),
            Err(BenchError::BadFrametime { index: 0, .. }),
        ));
    }

    // Recorded fact: 200 frames from a real MangoHud v0.8.1 capture (vkcube, RTX 2060 / Ryzen 3700X).
    // No Square Enix bytes; just the tool's own log of a trivial renderer.
    const FIXTURE: &str = include_str!("../tests/fixtures/mangohud_frametime.csv");

    #[test]
    fn parses_a_real_mangohud_capture() {
        let log = FrameLog::from_mangohud_csv(FIXTURE).unwrap();
        assert_eq!(log.frametimes_ms.len(), 200);
        assert_eq!(log.metadata["gpu"], "NVIDIA GeForce RTX 2060");
        assert_eq!(log.metadata["cpu"], "AMD Ryzen 7 3700X 8-Core Processor");

        let stats = log.stats().unwrap();
        // The lows never exceed the average, and average FPS tracks the mean frametime.
        assert!(stats.low_0_1pct <= stats.low_1pct + 1e-9);
        assert!(stats.low_1pct <= stats.average_fps + 1e-9);
        close(stats.average_fps, 1000.0 / stats.frametime_mean_ms);

        // Rounded so the golden is stable across platforms.
        insta::assert_snapshot!(format!(
            "frames={} duration_s={:.3} avg_fps={:.3} low_1pct={:.3} low_0_1pct={:.3} \
             frametime_mean_ms={:.3} frametime_stddev_ms={:.3}",
            stats.frame_count,
            stats.duration_s,
            stats.average_fps,
            stats.low_1pct,
            stats.low_0_1pct,
            stats.frametime_mean_ms,
            stats.frametime_stddev_ms,
        ));
    }

    #[test]
    fn an_impossible_first_sample_is_dropped_as_an_artifact() {
        // Some MangoHud builds log a garbage first row: a frametime longer than the process has
        // even been alive (elapsed is uptime in ns). Seen live under the Steam Linux Runtime.
        let csv = "fps,frametime,elapsed\n\
                   1.15165e-06,8.68319e+08,191224836\n\
                   27.3193,36.6042,227826535\n\
                   228.859,4.3695,566849246\n";
        let log = FrameLog::from_mangohud_csv(csv).unwrap();
        assert_eq!(log.artifacts_dropped, 1);
        assert_eq!(log.frametimes_ms, vec![36.6042, 4.3695]);
    }

    #[test]
    fn a_header_less_log_is_rejected() {
        assert_eq!(
            FrameLog::from_mangohud_csv("nonsense\n1,2,3\n"),
            Err(BenchError::NoDataHeader),
        );
    }

    #[test]
    fn a_bad_frametime_cell_names_its_line() {
        let csv = "fps,frametime,elapsed\n60,16.6,1\n60,oops,2\n";
        assert_eq!(
            FrameLog::from_mangohud_csv(csv),
            Err(BenchError::MalformedRow {
                line: 3,
                reason: "frametime is not a number",
            }),
        );
    }
}
