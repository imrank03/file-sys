use aya::maps::AsyncPerfEventArray;
use aya::util::online_cpus;
use aya::{include_bytes_aligned, Bpf};
use aya::{programs::Lsm, Btf};
use aya_log::BpfLogger;
use bytes::BytesMut;
use clap::Parser;
use log::info;
use tokio::signal;
#[derive(Debug, Parser)]
struct Opt {}
use file_sys_common::SuidEvent;

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    env_logger::init();
    let _opt = Opt::parse();

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    #[cfg(debug_assertions)]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/debug/file-sys"
    ))?;
    #[cfg(not(debug_assertions))]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/file-sys"
    ))?;
    BpfLogger::init(&mut bpf)?;
    let btf = Btf::from_sys_fs()?;
    let program: &mut Lsm = bpf.program_mut("file_open").unwrap().try_into()?;
    program.load("file_open", &btf)?;
    program.attach()?;

    // Process events from the perf buffer
    let cpus = online_cpus()?;
    let num_cpus = cpus.len();
    let mut events = AsyncPerfEventArray::try_from(bpf.take_map("NET_EVENTS").unwrap())?;
    println!("hello");
    for cpu in cpus {
        let mut buf = events.open(cpu, None)?;

        tokio::task::spawn(async move {
            let mut buffers = (0..num_cpus)
                .map(|_| BytesMut::with_capacity(10240))
                .collect::<Vec<_>>();

            loop {
                let events = buf.read_events(&mut buffers).await.unwrap();
                for i in 0..events.read {
                    // read the event
                    let buf = &mut buffers[i];
                    let ptr = buf.as_ptr() as *const SuidEvent;
                    let data = unsafe { ptr.read_unaligned() };

                    let pathname =
                        String::from_utf8(data.path.to_vec()).unwrap_or("Unknown".to_owned());

                    info!("file_open: path: {}", pathname);
                }
            }
        });
    }
    info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    info!("Exiting...");

    Ok(())
}
