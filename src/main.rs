use std::env;
use std::fs;
use std::process::Command;
use std::str;
use std::{thread, time::Duration};

fn get_uptime() -> f64 {
    fs::read_to_string("/proc/uptime")
        .expect("Could not read /proc/uptime")
        .split_whitespace()
        .next()
        .unwrap()
        .parse()
        .unwrap()
}

struct ProcStat {
    utime: i64,
    stime: i64,
    cutime: i64,
    cstime: i64,
    start_time: i64,
}

fn get_stat(pid: i32) -> ProcStat {
    let mut stats = fs::read_to_string(format!("/proc/{}/stat", pid))
        .expect("Stat file not found")
        .split_whitespace()
        .map(|s| s.parse::<i64>())
        .collect::<Vec<_>>();

    ProcStat {
        utime: stats.swap_remove(14 - 1).unwrap(),
        stime: stats.swap_remove(15 - 1).unwrap(),
        cutime: stats.swap_remove(16 - 1).unwrap(),
        cstime: stats.swap_remove(17 - 1).unwrap(),
        start_time: stats.swap_remove(22 - 1).unwrap(),
    }
}

fn get_clock_tick() -> i32 {
    let output = Command::new("getconf")
        .arg("CLK_TCK")
        .output()
        .expect("getconf failed")
        .stdout;

    str::from_utf8(&output).unwrap().trim().parse().unwrap()
}

fn total_ticks(stat: &ProcStat, include_children: bool) -> i64 {
    let parent_time = stat.utime + stat.stime;
    if include_children {
        parent_time + stat.cutime + stat.cstime
    } else {
        parent_time
    }
}

fn total_seconds(uptime: f64, starttime: i64, tick: i32) -> f64 {
    uptime - ((starttime / tick as i64) as f64)
}

fn cpu_usage(tick_diff: i64, time_diff: f64, tick: i32) -> f64 {
    100.0_f64 * ((tick_diff / tick as i64) as f64 / time_diff)
}

fn main() {
    let pid: i32 = env::args().collect::<Vec<String>>()[1].parse().unwrap();
    let tick = get_clock_tick();

    let initial_uptime = get_uptime();
    let initial_stat = get_stat(pid);
    let mut prev_total_ticks = total_ticks(&initial_stat, true);
    let mut prev_total_seconds = total_seconds(initial_uptime, initial_stat.start_time, tick);

    loop {
        let uptime = get_uptime();
        let stat = get_stat(pid);
        let total_ticks = total_ticks(&stat, true);
        let total_seconds = total_seconds(uptime, stat.start_time, tick);
        println!(
            "CPU: {}%",
            cpu_usage(
                total_ticks - prev_total_ticks,
                total_seconds - prev_total_seconds,
                tick
            )
        );

        prev_total_ticks = total_ticks;
        prev_total_seconds = total_seconds;

        thread::sleep(Duration::from_millis(1000));
    }
}
