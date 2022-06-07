use std::collections::HashSet;
use std::env;
use std::sync::{mpsc, Arc, Mutex};
use std::{thread, time::Duration};

use anyhow::{Context, Result};
use pcap::Device;
use procfs::net::TcpNetEntry;
use procfs::process::FDInfo;
use procfs::{page_size, process::FDTarget, process::Process, process::Stat, CpuInfo, KernelStats};

// Logic stolen from htop's LinuxProcessList_scanCPUTime
// Returns total ticks of CPU
fn total_cpu_time() -> Result<u64> {
    let cpu = KernelStats::new()?.total;
    let user = cpu.user - cpu.guest.unwrap_or(0);
    let nice = cpu.nice - cpu.guest_nice.unwrap_or(0);
    let total_idle = cpu.idle + cpu.iowait.unwrap_or(0);
    let total_system = cpu.system + cpu.irq.unwrap_or(0) + cpu.softirq.unwrap_or(0);
    let total_virt = cpu.guest.unwrap_or(0) + cpu.guest_nice.unwrap_or(0);
    Ok(user + nice + total_system + total_idle + total_virt + cpu.steal.unwrap_or(0))
}

fn period(ticks: u64, prev_ticks: u64, num_cores: usize) -> f64 {
    ticks.saturating_sub(prev_ticks) as f64 / num_cores as f64
}

fn cpu_usage(stat: &Stat, prev_stat: &Stat, period: f64) -> f64 {
    ((stat.utime + stat.stime) - (prev_stat.utime + prev_stat.stime)) as f64 / period * 100.0
}

fn process(pid: i32) -> Result<Process> {
    Process::new(pid).context(format!("Could not locate process with pid {}", pid))
}

// Create a Berkley Packet Filter to find packets belonging to one of the ports in use by the process
// Packets are considered a match if they have the same protocol, host address, and destination address
// Therefore, we create a filter like:
// (host 127.0.0.1 and host 127.0.0.1 and port 33791 and port 60914) or (...)
fn build_packet_filter<F, T>(fd: F, tcp: T) -> String
where
    F: IntoIterator<Item = FDInfo>,
    T: IntoIterator<Item = TcpNetEntry>,
{
    // Given a list of file descriptors, find the inodes of those that are sockets
    let inodes: HashSet<_> = fd
        .into_iter()
        .filter_map(|fd| match fd.target {
            FDTarget::Socket(inode) => Some(inode),
            _ => None,
        })
        .collect();

    // Add to the filter each TCP entry that corresponds to a socket in the fd list
    tcp.into_iter()
        .filter(|entry| inodes.contains(&entry.inode))
        .map(|entry| {
            format!(
                "(host {} and host {} and port {} and port {})",
                entry.local_address.ip(),
                entry.remote_address.ip(),
                entry.local_address.port(),
                entry.remote_address.port()
            )
        })
        .collect::<Vec<_>>()
        .join(" or ")
}

fn main() -> Result<()> {
    let pid: i32 = env::args().collect::<Vec<String>>()[1].parse().unwrap();

    let page_size = page_size()?;
    let cores = CpuInfo::new()?.num_cores();

    let process = process(pid)?;
    let mut prev_stat = process.stat.clone();
    let mut prev_total_ticks = total_cpu_time()?;

    let io = process.io()?;
    let (mut prev_bytes_read, mut prev_bytes_written) = (io.read_bytes, io.write_bytes);

    let bpf = build_packet_filter(process.fd()?, procfs::net::tcp()?);
    println!("{bpf}");

    let mut capture = Device::lookup()?.open()?;
    capture.filter(&bpf, true)?;

    let counter = Arc::new(Mutex::new(0_u64));
    let thread_counter = Arc::clone(&counter);

    let (sender, receiver) = mpsc::channel::<String>();

    thread::spawn(move || {
        while let Ok(packet) = capture.next() {
            let mut bytes = thread_counter.lock().unwrap();
            *bytes += packet.header.len as u64;
            drop(bytes);

            if let Ok(filter) = receiver.try_recv() {
                println!("Received new filter");
                capture.filter(&filter, true).unwrap();
            }
        }
    });

    let mut prev_net_bytes = 0;

    loop {
        let delay_ms = 1000;
        let delay_s = delay_ms / 1000;
        thread::sleep(Duration::from_millis(delay_ms));

        let stat = process.stat()?; // stat() re-fetches the data
        let total_ticks = total_cpu_time()?;
        let period = period(total_ticks, prev_total_ticks, cores);
        let cpu = cpu_usage(&stat, &prev_stat, period);

        prev_stat = stat;
        prev_total_ticks = total_ticks;

        let mem = process.statm()?.resident * page_size as u64;

        let io = process.io()?;
        let read_bps = (io.read_bytes - prev_bytes_read) / delay_s;
        let write_bps = (io.write_bytes - prev_bytes_written) / delay_s;
        let io_rate = read_bps + write_bps;

        prev_bytes_read = io.read_bytes;
        prev_bytes_written = io.write_bytes;

        let net_bytes = *counter.lock().unwrap();
        let byte_diff = (net_bytes - prev_net_bytes) / delay_s;
        prev_net_bytes = net_bytes;

        println!(
            "CPU: {:.1}% Mem: {}B I/O: {}B Net: {}B",
            cpu, mem, io_rate, byte_diff
        );

        sender.send(build_packet_filter(process.fd()?, procfs::net::tcp()?))?;
    }
}
