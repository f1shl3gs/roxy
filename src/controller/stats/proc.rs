use std::io::Read;

use libc::{sysconf, _SC_PAGESIZE};
use serde::Serialize;

const MAXFD_PATTERN: &str = "Max open files";
const USER_HZ: f64 = 100.0;

#[derive(Serialize)]
pub struct ProcStat {
    pub open_fds: usize,
    pub max_fds: usize,
    pub cpu_seconds: f64,
    pub threads: usize,
    pub start: f64,
    pub vss: usize,
    pub rss: usize,
}

impl ProcStat {
    pub fn read() -> Result<Self, std::io::Error> {
        let pid = unsafe { libc::getpid() as i32 };
        let open_fds = open_fds(pid)?;
        let max_fds = max_fds(pid)?;
        let (cpu_seconds, threads, start, vss, rss) = get_proc_stat("/proc", pid)?;

        Ok(Self {
            open_fds,
            max_fds,
            cpu_seconds,
            threads,
            start,
            vss,
            rss,
        })
    }
}

fn open_fds(pid: i32) -> Result<usize, std::io::Error> {
    let path = format!("/proc/{}/fd", pid);
    std::fs::read_dir(path)?.fold(Ok(0), |acc, i| {
        let mut acc = acc?;
        let ty = i?.file_type()?;
        if !ty.is_dir() {
            acc += 1;
        }

        Ok(acc)
    })
}

fn max_fds(pid: i32) -> Result<usize, std::io::Error> {
    let mut buffer = String::new();
    std::fs::File::open(&format!("/proc/{}/limits", pid))
        .and_then(|mut f| f.read_to_string(&mut buffer))?;

    find_statistic(&buffer, MAXFD_PATTERN)
}

fn find_statistic(all: &str, pat: &str) -> Result<usize, std::io::Error> {
    if let Some(idx) = all.find(pat) {
        let mut iter = (all[idx + pat.len()..]).split_whitespace();
        if let Some(v) = iter.next() {
            return v
                .parse()
                .map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidInput, err));
        }
    }

    Err(std::io::Error::from(std::io::ErrorKind::InvalidInput))
}

fn get_proc_stat(root: &str, pid: i32) -> Result<(f64, usize, f64, usize, usize), std::io::Error> {
    let path = format!("{}/{}/stat", root, pid);
    let content = std::fs::read_to_string(&path)?;
    let parts = content.split_ascii_whitespace().collect::<Vec<_>>();

    let utime = parts[13].parse().unwrap_or(0f64);
    let stime = parts[14].parse().unwrap_or(0f64);
    let threads = parts[19].parse().unwrap_or(0usize);
    let start_time = parts[21].parse().unwrap_or(0f64);
    let vsize = parts[22].parse().unwrap_or(0usize);
    let rss = parts[23].parse().unwrap_or(0usize);

    // Get page_size at runtime
    let page_size = unsafe { sysconf(_SC_PAGESIZE) as usize };

    Ok((
        (utime + stime) / USER_HZ,
        threads,
        (start_time) / USER_HZ,
        vsize,
        rss * page_size,
    ))
}
