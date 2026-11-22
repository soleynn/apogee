//! Per-run metrics for comparing runners, beyond the frame-consistency figures the runtime computes.
//!
//! The runtime's [`FrameLog`] keeps only the frametimes, so this reads the MangoHud CSV a second
//! time for the columns a comparison also needs: the per-frame FPS that marks loading screens, and
//! the GPU telemetry that marks a run as throttled. Everything here is computed over the frames
//! outside loading windows, because a loading screen is the same on every runner and would otherwise
//! dominate the tail figures.
//!
//! The runtime's figures are reused rather than redefined: the measured-frame averages and lows are
//! [`BenchStats`] over the measured frametimes, so the two can never disagree on what a 1% low is.

use apogee_core::{BenchStats, FrameLog};
use serde::Serialize;

/// A frame whose FPS is below this is a loading-screen candidate.
const LOADING_FPS: f64 = 5.0;
/// A run of loading-candidate frames counts as a loading window only once it lasts this long. A
/// single long frame mid-scene is a stall to be counted, not a load to be excluded.
const LOADING_MIN_MS: f64 = 1000.0;
/// The two fixed stall thresholds, in milliseconds.
const STALL_MS: [f64; 2] = [50.0, 100.0];
/// A frame over this multiple of the rolling median frametime is a stall relative to its scene.
const STALL_MEDIAN_FACTOR: f64 = 2.0;
/// Frames either side of a frame that its rolling median is taken over.
const ROLLING_HALF_WINDOW: usize = 60;
/// A GPU clock this fraction below the run median is a dip.
const CLOCK_DIP_FRACTION: f64 = 0.05;
/// A dip lasting longer than this marks the run invalid.
const CLOCK_DIP_MAX_MS: f64 = 2000.0;
/// More dropped instrumentation rows than this marks the run invalid.
const MAX_ARTIFACTS: usize = 1;

/// Everything `bench analyze` reports for one log.
#[derive(Debug, Serialize)]
pub(crate) struct RunReport {
    /// The runtime's figures over every frame the log kept.
    pub(crate) all_frames: BenchStats,
    /// How many rows the runtime dropped as instrumentation artifacts.
    pub(crate) artifacts_dropped: usize,
    /// The excluded loading screens.
    pub(crate) loading: Loading,
    /// The figures over the frames outside loading windows; `None` when every frame was loading.
    pub(crate) measured: Option<Measured>,
    /// Which telemetry columns carried real readings.
    pub(crate) telemetry: Telemetry,
    /// Why the run should or should not be ranked.
    pub(crate) validity: Validity,
}

#[derive(Debug, Serialize)]
pub(crate) struct Loading {
    /// How many loading windows were excluded.
    pub(crate) windows: usize,
    /// Their summed length, in seconds.
    pub(crate) seconds: f64,
}

#[derive(Debug, Serialize)]
pub(crate) struct Measured {
    /// The runtime's figures over the measured frames.
    pub(crate) stats: BenchStats,
    /// 99th-percentile frametime (nearest rank), in milliseconds.
    pub(crate) p99_ms: f64,
    /// 99.9th-percentile frametime (nearest rank), in milliseconds.
    pub(crate) p99_9_ms: f64,
    /// Frames over 50 ms.
    pub(crate) stalls_over_50ms: Stalls,
    /// Frames over 100 ms.
    pub(crate) stalls_over_100ms: Stalls,
    /// Frames over twice the median of the frames around them.
    pub(crate) stalls_over_2x_median: Stalls,
    /// Mean absolute difference between consecutive frametimes, in milliseconds. Pairs that span a
    /// loading window are not consecutive. `None` when no two measured frames are adjacent.
    pub(crate) jitter_ms: Option<f64>,
}

#[derive(Debug, Default, Serialize)]
pub(crate) struct Stalls {
    pub(crate) count: usize,
    /// The stalled frames' summed frametime, in milliseconds.
    pub(crate) total_ms: f64,
}

#[derive(Debug, Serialize)]
pub(crate) struct Telemetry {
    /// `gpu_core_clock` is present and non-zero somewhere. Some captures log it as zero throughout.
    pub(crate) gpu_core_clock: bool,
    /// `gpu_temp` is present and non-zero somewhere.
    pub(crate) gpu_temp: bool,
    /// The hottest GPU reading over the measured frames, when it was logged.
    pub(crate) gpu_temp_max: Option<f64>,
}

#[derive(Debug, Serialize)]
pub(crate) struct Validity {
    /// The longest stretch the GPU clock spent over 5% below its run median, in seconds; `None`
    /// without clock telemetry.
    pub(crate) longest_clock_dip_s: Option<f64>,
    /// That stretch exceeded two seconds; `None` without clock telemetry, which is not a pass.
    pub(crate) clock_dipped: Option<bool>,
    /// More than one row was dropped as an instrumentation artifact.
    pub(crate) too_many_artifacts: bool,
    /// Nothing above marks the run invalid. A run with no clock telemetry can still be valid here;
    /// the caller then has to judge throttling from another source.
    pub(crate) valid: bool,
}

/// One kept frame: its frametime and whichever optional columns it carried.
#[derive(Debug, Clone, Copy)]
struct Frame {
    ft_ms: f64,
    fps: Option<f64>,
    gpu_clock: Option<f64>,
    gpu_temp: Option<f64>,
}

/// Analyze one MangoHud CSV.
///
/// # Errors
///
/// Whatever the runtime's parser or statistics refuse (no data header, a malformed row, no frames),
/// or a disagreement between the two parses about which rows are frames.
pub(crate) fn analyze(text: &str) -> Result<RunReport, Box<dyn std::error::Error>> {
    let log = FrameLog::from_mangohud_csv(text)?;
    let all_frames = log.stats()?;
    let frames = parse_frames(text);
    if frames.len() != log.frametimes_ms.len() {
        return Err(format!(
            "the per-frame columns read {} frames where the frametimes read {}",
            frames.len(),
            log.frametimes_ms.len()
        )
        .into());
    }

    let (segments, loading) = split_loading(&frames);
    let measured_frames: Vec<f64> = segments.iter().flatten().map(|f| f.ft_ms).collect();
    let measured = if measured_frames.is_empty() {
        None
    } else {
        Some(measure(&segments, &measured_frames)?)
    };

    let has = |pick: fn(&Frame) -> Option<f64>| frames.iter().filter_map(pick).any(|v| v > 0.0);
    let telemetry = Telemetry {
        gpu_core_clock: has(|f| f.gpu_clock),
        gpu_temp: has(|f| f.gpu_temp),
        gpu_temp_max: has(|f| f.gpu_temp)
            .then(|| {
                segments
                    .iter()
                    .flatten()
                    .filter_map(|f| f.gpu_temp)
                    .reduce(f64::max)
            })
            .flatten(),
    };

    let longest_clock_dip_s = telemetry
        .gpu_core_clock
        .then(|| longest_clock_dip_ms(&segments).map(|ms| ms / 1000.0))
        .flatten();
    let clock_dipped = longest_clock_dip_s.map(|s| s * 1000.0 > CLOCK_DIP_MAX_MS);
    let too_many_artifacts = log.artifacts_dropped > MAX_ARTIFACTS;
    Ok(RunReport {
        all_frames,
        artifacts_dropped: log.artifacts_dropped,
        loading,
        measured,
        telemetry,
        validity: Validity {
            longest_clock_dip_s,
            clock_dipped,
            too_many_artifacts,
            valid: !too_many_artifacts && clock_dipped != Some(true),
        },
    })
}

/// Read the per-frame columns, keeping exactly the rows the runtime's parser keeps. Called only
/// after that parser accepted the log, so the header and every frametime cell are known good.
fn parse_frames(text: &str) -> Vec<Frame> {
    let lines: Vec<&str> = text.lines().collect();
    let Some(header_idx) = lines
        .iter()
        .position(|l| l.split(',').next() == Some("fps") && l.split(',').any(|c| c == "frametime"))
    else {
        return Vec::new();
    };
    let header: Vec<&str> = lines[header_idx].split(',').map(str::trim).collect();
    let column = |name: &str| header.iter().position(|c| *c == name);
    let (Some(ft), elapsed) = (column("frametime"), column("elapsed")) else {
        return Vec::new();
    };
    let (fps, clock, temp) = (column("fps"), column("gpu_core_clock"), column("gpu_temp"));

    let mut frames = Vec::new();
    for line in &lines[header_idx + 1..] {
        if line.trim().is_empty() {
            continue;
        }
        let cells: Vec<&str> = line.split(',').collect();
        let number = |i: Option<usize>| {
            i.and_then(|i| cells.get(i))
                .and_then(|c| c.trim().parse::<f64>().ok())
                .filter(|v| v.is_finite())
        };
        let Some(ft_ms) = number(Some(ft)) else {
            continue;
        };
        // The same artifact rule as the runtime's parser: a frame longer than the process had been
        // alive is not a frame.
        if number(elapsed).is_some_and(|ns| ft_ms > ns / 1e6) {
            continue;
        }
        frames.push(Frame {
            ft_ms,
            fps: number(fps),
            gpu_clock: number(clock),
            gpu_temp: number(temp),
        });
    }
    frames
}

/// Split the frames into the measured stretches between loading windows.
fn split_loading(frames: &[Frame]) -> (Vec<Vec<Frame>>, Loading) {
    let slow = |f: &Frame| f.fps.unwrap_or(1000.0 / f.ft_ms) < LOADING_FPS;
    let mut segments = Vec::new();
    let mut current = Vec::new();
    let mut loading = Loading {
        windows: 0,
        seconds: 0.0,
    };
    let mut i = 0;
    while i < frames.len() {
        if !slow(&frames[i]) {
            current.push(frames[i]);
            i += 1;
            continue;
        }
        let end = frames[i..]
            .iter()
            .position(|f| !slow(f))
            .map_or(frames.len(), |n| i + n);
        let run = &frames[i..end];
        let run_ms: f64 = run.iter().map(|f| f.ft_ms).sum();
        if run_ms >= LOADING_MIN_MS {
            loading.windows += 1;
            loading.seconds += run_ms / 1000.0;
            segments.push(std::mem::take(&mut current));
        } else {
            current.extend_from_slice(run);
        }
        i = end;
    }
    segments.push(current);
    segments.retain(|s| !s.is_empty());
    (segments, loading)
}

fn measure(segments: &[Vec<Frame>], measured: &[f64]) -> Result<Measured, apogee_core::BenchError> {
    let stats = BenchStats::from_frametimes(measured)?;
    let mut sorted = measured.to_vec();
    sorted.sort_by(f64::total_cmp);

    let over = |threshold: f64| {
        measured
            .iter()
            .filter(|&&ft| ft > threshold)
            .fold(Stalls::default(), |s, &ft| Stalls {
                count: s.count + 1,
                total_ms: s.total_ms + ft,
            })
    };

    let mut relative = Stalls::default();
    let mut jitter_sum = 0.0;
    let mut jitter_pairs = 0usize;
    for segment in segments {
        let fts: Vec<f64> = segment.iter().map(|f| f.ft_ms).collect();
        for (i, &ft) in fts.iter().enumerate() {
            if ft > STALL_MEDIAN_FACTOR * rolling_median(&fts, i) {
                relative.count += 1;
                relative.total_ms += ft;
            }
        }
        for pair in fts.windows(2) {
            jitter_sum += (pair[1] - pair[0]).abs();
            jitter_pairs += 1;
        }
    }

    Ok(Measured {
        stats,
        p99_ms: nearest_rank(&sorted, 0.99),
        p99_9_ms: nearest_rank(&sorted, 0.999),
        stalls_over_50ms: over(STALL_MS[0]),
        stalls_over_100ms: over(STALL_MS[1]),
        stalls_over_2x_median: relative,
        jitter_ms: (jitter_pairs > 0).then(|| jitter_sum / jitter_pairs as f64),
    })
}

/// The nearest-rank percentile of an ascending, non-empty slice.
fn nearest_rank(sorted: &[f64], q: f64) -> f64 {
    let rank = (q * sorted.len() as f64).ceil() as usize;
    sorted[rank.clamp(1, sorted.len()) - 1]
}

/// The median of the frames within [`ROLLING_HALF_WINDOW`] of `i`, `i` included, clipped at the
/// segment's ends. An even count takes the mean of the middle two.
fn rolling_median(fts: &[f64], i: usize) -> f64 {
    let lo = i.saturating_sub(ROLLING_HALF_WINDOW);
    let hi = (i + ROLLING_HALF_WINDOW + 1).min(fts.len());
    let mut window = fts[lo..hi].to_vec();
    window.sort_by(f64::total_cmp);
    let n = window.len();
    if n % 2 == 1 {
        window[n / 2]
    } else {
        (window[n / 2 - 1] + window[n / 2]) / 2.0
    }
}

/// The longest contiguous stretch of measured time the GPU clock spent below its dip threshold, in
/// milliseconds. Frames that logged no clock (or zero) neither extend nor break a stretch. `None`
/// when no measured frame logged a clock.
fn longest_clock_dip_ms(segments: &[Vec<Frame>]) -> Option<f64> {
    let mut clocks: Vec<f64> = segments
        .iter()
        .flatten()
        .filter_map(|f| f.gpu_clock)
        .filter(|&c| c > 0.0)
        .collect();
    if clocks.is_empty() {
        return None;
    }
    clocks.sort_by(f64::total_cmp);
    let median = clocks[clocks.len() / 2];
    let floor = median * (1.0 - CLOCK_DIP_FRACTION);
    let mut longest = 0.0f64;
    for segment in segments {
        let mut current = 0.0;
        for frame in segment {
            match frame.gpu_clock.filter(|&c| c > 0.0) {
                Some(clock) if clock < floor => current += frame.ft_ms,
                Some(_) => current = 0.0,
                None => {}
            }
            longest = longest.max(current);
        }
    }
    Some(longest)
}

#[cfg(test)]
mod tests {
    use super::*;

    const HEADER: &str = "fps,frametime,gpu_temp,gpu_core_clock,elapsed\n";

    /// A log of `(frametime, gpu_temp, gpu_clock)` rows, `fps` derived and `elapsed` accumulated.
    fn csv(rows: &[(f64, f64, f64)]) -> String {
        let mut out = String::from(HEADER);
        let mut elapsed_ns = 1e9;
        for &(ft, temp, clock) in rows {
            elapsed_ns += ft * 1e6;
            out.push_str(&format!(
                "{},{ft},{temp},{clock},{elapsed_ns}\n",
                1000.0 / ft
            ));
        }
        out
    }

    fn steady(n: usize, ft: f64) -> Vec<(f64, f64, f64)> {
        vec![(ft, 60.0, 1800.0); n]
    }

    #[test]
    fn a_log_with_no_frames_is_refused() {
        assert!(analyze(HEADER).is_err());
    }

    #[test]
    fn an_all_loading_log_has_no_measured_figures_but_still_reports() {
        // Three seconds at 2 FPS: one loading window, nothing left to measure.
        let report = analyze(&csv(&steady(6, 500.0))).unwrap();
        assert_eq!(report.loading.windows, 1);
        assert!((report.loading.seconds - 3.0).abs() < 1e-9);
        assert!(report.measured.is_none());
        assert_eq!(report.all_frames.frame_count, 6);
    }

    #[test]
    fn a_short_freeze_is_a_stall_not_a_load() {
        let mut rows = steady(200, 10.0);
        rows[100] = (400.0, 60.0, 1800.0);
        let report = analyze(&csv(&rows)).unwrap();
        assert_eq!(report.loading.windows, 0);
        let m = report.measured.unwrap();
        assert_eq!(m.stalls_over_50ms.count, 1);
        assert_eq!(m.stalls_over_100ms.count, 1);
        assert_eq!(m.stalls_over_2x_median.count, 1);
        assert!((m.stalls_over_100ms.total_ms - 400.0).abs() < 1e-9);
    }

    #[test]
    fn a_loading_window_splits_the_run_and_breaks_jitter_pairs() {
        // 10 ms frames, a two-second load, then 20 ms frames. Across the load the frametime
        // doubles, which must not count as jitter: those two frames were never adjacent on screen.
        let mut rows = steady(50, 10.0);
        rows.extend(steady(4, 500.0));
        rows.extend(steady(50, 20.0));
        let report = analyze(&csv(&rows)).unwrap();
        assert_eq!(report.loading.windows, 1);
        let m = report.measured.unwrap();
        assert_eq!(m.stats.frame_count, 100);
        assert_eq!(m.jitter_ms, Some(0.0));
        // The relative rule sees each scene against its own median, so neither scene stalls.
        assert_eq!(m.stalls_over_2x_median.count, 0);
        assert_eq!(m.stalls_over_50ms.count, 0);
    }

    #[test]
    fn jitter_sees_order_that_the_spread_cannot() {
        // Same frametimes, so the same mean and spread; alternating is jittery, grouped is not.
        let alternating: Vec<_> = (0..100)
            .map(|i| (if i % 2 == 0 { 10.0 } else { 20.0 }, 60.0, 1800.0))
            .collect();
        let mut grouped = steady(50, 10.0);
        grouped.extend(steady(50, 20.0));
        let a = analyze(&csv(&alternating)).unwrap().measured.unwrap();
        let g = analyze(&csv(&grouped)).unwrap().measured.unwrap();
        assert!((a.stats.frametime_stddev_ms - g.stats.frametime_stddev_ms).abs() < 1e-9);
        assert!((a.jitter_ms.unwrap() - 10.0).abs() < 1e-9);
        assert!((g.jitter_ms.unwrap() - 10.0 / 99.0).abs() < 1e-9);
    }

    #[test]
    fn percentiles_are_nearest_rank() {
        // 1000 frames 1..=1000 ms: p99 is the 990th, p99.9 the 999th. Fps stays above the
        // loading line by giving the frames an explicit fps column.
        let mut text = String::from("fps,frametime,elapsed\n");
        for ft in 1..=1000 {
            text.push_str(&format!("60,{ft},1e15\n"));
        }
        let m = analyze(&text).unwrap().measured.unwrap();
        assert_eq!(m.p99_ms, 990.0);
        assert_eq!(m.p99_9_ms, 999.0);
    }

    #[test]
    fn missing_telemetry_columns_leave_the_flags_unknown_rather_than_passing() {
        let text = "fps,frametime,elapsed\n60,16.6,100000000\n60,16.7,200000000\n";
        let report = analyze(text).unwrap();
        assert!(!report.telemetry.gpu_core_clock && !report.telemetry.gpu_temp);
        assert_eq!(report.telemetry.gpu_temp_max, None);
        assert_eq!(report.validity.clock_dipped, None);
        assert!(report.validity.valid);
    }

    #[test]
    fn telemetry_logged_as_zero_is_treated_as_absent() {
        let rows = vec![(10.0, 0.0, 0.0); 20];
        let report = analyze(&csv(&rows)).unwrap();
        assert!(!report.telemetry.gpu_core_clock);
        assert_eq!(report.validity.clock_dipped, None);
    }

    #[test]
    fn a_sustained_clock_dip_invalidates_the_run_and_a_brief_one_does_not() {
        // 1000 frames at 10 ms; the clock drops 10% for 250 frames (2.5 s) or for 150 (1.5 s).
        let dip = |frames: usize| {
            let mut rows = steady(1000, 10.0);
            for row in &mut rows[100..100 + frames] {
                row.2 = 1600.0;
            }
            analyze(&csv(&rows)).unwrap().validity
        };
        let long = dip(250);
        assert_eq!(long.clock_dipped, Some(true));
        assert!(!long.valid);
        let brief = dip(150);
        assert_eq!(brief.clock_dipped, Some(false));
        assert!(brief.valid);
    }

    #[test]
    fn more_than_one_dropped_row_invalidates_the_run() {
        // Two rows longer than the uptime at which they were logged.
        let text = "fps,frametime,elapsed\n1,5000,1000000\n1,5000,2000000\n60,16,9000000000\n";
        let report = analyze(text).unwrap();
        assert_eq!(report.artifacts_dropped, 2);
        assert_eq!(report.all_frames.frame_count, 1);
        assert!(report.validity.too_many_artifacts && !report.validity.valid);
    }

    #[test]
    fn an_unreadable_fps_cell_falls_back_to_the_frametime() {
        // The data header always starts with `fps`, so the column exists; a cell that is not a
        // number is what has to fall back, or a load would go unnoticed.
        let mut text = String::from("fps,frametime\n");
        for _ in 0..4 {
            text.push_str("n/a,400\n");
        }
        let report = analyze(&text).unwrap();
        assert_eq!(report.loading.windows, 1);
    }
}
