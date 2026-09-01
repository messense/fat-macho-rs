//! Micro benchmark, run with `cargo bench`.
//!
//! Inputs default to the small test fixtures; point the environment
//! variables `BENCH_THIN`, `BENCH_FAT` and `BENCH_AR` at large real world
//! binaries for more meaningful numbers.
use std::hint::black_box;
use std::time::{Duration, Instant};

use fat_macho::{FatReader, FatWriter};

fn input(var: &str, default: &str) -> (String, Vec<u8>) {
    let path = std::env::var(var).unwrap_or_else(|_| default.to_string());
    let data = std::fs::read(&path).unwrap_or_else(|e| panic!("{}: {}", path, e));
    (path, data)
}

/// Run `f` repeatedly for ~`budget` and report the best / median iteration.
///
/// Cheap operations are batched so that one sample is well above the timer
/// resolution (~41ns on Apple Silicon).
fn bench(name: &str, budget: Duration, mut f: impl FnMut()) {
    // warm up and calibrate the batch size
    let t = Instant::now();
    f();
    let single = t.elapsed();
    let target = Duration::from_micros(50);
    let batch = if single >= target {
        1
    } else {
        (target.as_nanos() / single.as_nanos().max(1)).clamp(1, 100_000) as u32
    };
    let mut samples = Vec::new();
    let start = Instant::now();
    while start.elapsed() < budget || samples.len() < 5 {
        let t = Instant::now();
        for _ in 0..batch {
            f();
        }
        samples.push(t.elapsed() / batch);
        if samples.len() >= 10_000 {
            break;
        }
    }
    samples.sort();
    let best = samples[0];
    let median = samples[samples.len() / 2];
    println!(
        "{:<40} best {:>12.3?}   median {:>12.3?}   ({} iters x {})",
        name,
        best,
        median,
        samples.len(),
        batch
    );
}

fn main() {
    let budget = Duration::from_millis(
        std::env::var("BENCH_MS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(1500),
    );
    let (thin_path, thin) = input("BENCH_THIN", "tests/fixtures/thin_arm64");
    let (fat_path, fat) = input("BENCH_FAT", "tests/fixtures/hellofat");
    let (ar_path, ar) = input("BENCH_AR", "tests/fixtures/thin_arm64.a");
    let (_, other) = input("BENCH_OTHER", "tests/fixtures/thin_x86_64");
    println!("thin: {} ({} bytes)", thin_path, thin.len());
    println!("fat:  {} ({} bytes)", fat_path, fat.len());
    println!("ar:   {} ({} bytes)", ar_path, ar.len());
    println!("note: the `owned Vec` rows include cloning the input inside the timed loop");
    println!();

    for (name, data) in [("thin", &thin), ("fat", &fat), ("archive", &ar)] {
        bench(&format!("add {} (owned Vec)", name), budget, || {
            let mut w = FatWriter::new();
            w.add(black_box(data.clone())).unwrap();
            black_box(w);
        });
        bench(&format!("add {} (borrowed slice)", name), budget, || {
            let mut w = FatWriter::new();
            w.add(black_box(data.as_slice())).unwrap();
            black_box(w);
        });
    }

    let mut w = FatWriter::new();
    w.add(thin.as_slice()).unwrap();
    w.add(other.as_slice()).unwrap();
    bench("write_to Vec (thin + other, pre-sized)", budget, || {
        let mut out = Vec::with_capacity(w.total_size() as usize);
        w.write_to(&mut out).unwrap();
        black_box(out);
    });
    bench("write_to io::sink (thin + other)", budget, || {
        let mut out = std::io::sink();
        w.write_to(&mut out).unwrap();
    });
    let tmp = std::env::temp_dir().join("fat-macho-bench-out");
    bench("write_to_file (thin + other)", budget, || {
        w.write_to_file(&tmp).unwrap();
    });
    let _ = std::fs::remove_file(&tmp);

    bench("FatReader::new + extract (fat)", budget, || {
        let r = FatReader::new(black_box(&fat)).unwrap();
        black_box(r.extract("x86_64"));
        black_box(r.extract("arm64"));
    });
    bench("FatReader::new (thin -> NotFat)", budget, || {
        black_box(FatReader::new(black_box(&thin)).is_err());
    });
}
