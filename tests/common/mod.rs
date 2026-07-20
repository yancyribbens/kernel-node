#![allow(dead_code)]

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output};
use std::time::{Duration, Instant};

use corepc_node::{Conf, Node, P2P};

const READY_TIMEOUT: Duration = Duration::from_secs(30);
const STOP_TIMEOUT: Duration = Duration::from_secs(45);
const POLL_INTERVAL: Duration = Duration::from_millis(50);

const CLOSED_PEER: &str = "127.0.0.1:1";

pub fn start_bitcoind() -> Node {
    let exe = corepc_node::exe_path()
        .expect("resolve bitcoind: downloaded build, or BITCOIND_EXE, or bitcoind on PATH");
    let mut conf = Conf::default();
    conf.p2p = P2P::Yes;
    Node::with_conf(exe, &conf).unwrap()
}

pub struct TestNode {
    process: Child,
    datadir: PathBuf,
    _tempdir: tempfile::TempDir,
}

impl TestNode {
    pub fn start() -> Self {
        Self::start_connected(CLOSED_PEER)
    }

    pub fn start_connected(peer: impl std::fmt::Display) -> Self {
        let tempdir = tempfile::tempdir().unwrap();
        let datadir = tempdir.path().canonicalize().unwrap();
        let process = Command::new(env!("CARGO_BIN_EXE_node"))
            .arg("--network")
            .arg("regtest")
            .arg("--datadir")
            .arg(&datadir)
            .arg("--connect")
            .arg(peer.to_string())
            .spawn()
            .unwrap();
        let node = Self {
            process,
            datadir,
            _tempdir: tempdir,
        };
        node.wait_until_ready();
        node
    }

    pub fn cli(&self, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_cli"))
            .arg("--datadir")
            .arg(&self.datadir)
            .args(args)
            .output()
            .unwrap()
    }

    pub fn stop(mut self) {
        let out = self.cli(&["stop"]);
        assert!(
            out.status.success(),
            "cli stop failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        let deadline = Instant::now() + STOP_TIMEOUT;
        while Instant::now() < deadline {
            if self.process.try_wait().unwrap().is_some() {
                return;
            }
            std::thread::sleep(POLL_INTERVAL);
        }
        panic!("node did not exit within {STOP_TIMEOUT:?} after stop");
    }

    fn socket_path(&self) -> PathBuf {
        self.datadir.join("node.sock")
    }

    fn wait_until_ready(&self) {
        let deadline = Instant::now() + READY_TIMEOUT;
        while Instant::now() < deadline {
            if Path::new(&self.socket_path()).exists() {
                return;
            }
            std::thread::sleep(POLL_INTERVAL);
        }
        panic!("node did not create control socket within {READY_TIMEOUT:?}");
    }
}

impl Drop for TestNode {
    fn drop(&mut self) {
        let _ = self.process.kill();
        let _ = self.process.wait();
    }
}
