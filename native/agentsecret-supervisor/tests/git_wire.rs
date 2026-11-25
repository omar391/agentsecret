use agentsecret_supervisor::git_wire::{Packet, PacketReader, append_packet};
use std::fs;
use std::io::{Cursor, Write};
use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(0);
const MAX_EXCHANGE: usize = 4 * 1024 * 1024;

struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .ancestors()
            .nth(2)
            .unwrap();
        let tmp = root.join("tmp");
        fs::create_dir_all(&tmp).unwrap();
        let path = tmp.join(format!(
            "git-wire-{}-{}",
            std::process::id(),
            NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed)
        ));
        fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
        fs::create_dir(path.join("hooks")).unwrap();
        Self(path)
    }

    fn git(&self, cwd: &Path) -> Command {
        let mut command = Command::new("git");
        command
            .current_dir(cwd)
            .env_clear()
            .env("PATH", "/usr/bin:/bin:/usr/local/bin:/opt/homebrew/bin")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .args([
                "-c",
                &format!("core.hooksPath={}", self.0.join("hooks").display()),
                "-c",
                "user.name=Fixture",
                "-c",
                "user.email=fixture@example.invalid",
            ]);
        command
    }

    fn run(&self, cwd: &Path, args: &[&str]) -> Vec<u8> {
        let output = self.git(cwd).args(args).output().unwrap();
        assert!(output.status.success(), "fixture Git command failed");
        output.stdout
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn real_git_sideband_pack_survives_packet_framing_byte_for_byte() {
    let f = Fixture::new();
    let source = f.0.join("source");
    let destination = f.0.join("destination");
    fs::create_dir(&source).unwrap();
    fs::create_dir(&destination).unwrap();
    f.run(&source, &["init", "-q"]);
    f.run(&destination, &["init", "-q"]);
    // Binary data includes every byte value and is never interpreted as UTF-8.
    let original: Vec<u8> = (0..300_000)
        .map(|n| ((n * 131 + n / 251) % 256) as u8)
        .collect();
    fs::write(source.join("binary.dat"), &original).unwrap();
    f.run(&source, &["add", "binary.dat"]);
    f.run(&source, &["commit", "-qm", "binary fixture"]);
    let oid = String::from_utf8(f.run(&source, &["rev-parse", "HEAD:binary.dat"])).unwrap();
    let commit = String::from_utf8(f.run(&source, &["rev-parse", "HEAD"])).unwrap();
    let mut request = Vec::new();
    append_packet(
        &mut request,
        &Packet::Data(
            format!(
                "want {} side-band-64k ofs-delta no-progress\n",
                commit.trim()
            )
            .into_bytes(),
        ),
        MAX_EXCHANGE,
    )
    .unwrap();
    append_packet(&mut request, &Packet::Flush, MAX_EXCHANGE).unwrap();
    append_packet(
        &mut request,
        &Packet::Data(b"done\n".to_vec()),
        MAX_EXCHANGE,
    )
    .unwrap();
    let mut child = f
        .git(&source)
        .args(["upload-pack", "--stateless-rpc", "."])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(&request).unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success(), "upload-pack failed");
    assert!(output.stdout.len() < MAX_EXCHANGE);
    let mut reader = PacketReader::new(Cursor::new(&output.stdout), MAX_EXCHANGE);
    let mut encoded = Vec::new();
    let mut pack = Vec::new();
    while let Some(packet) = reader.read_packet().unwrap() {
        append_packet(&mut encoded, &packet, MAX_EXCHANGE).unwrap();
        if let Packet::Data(bytes) = packet {
            if bytes.first() == Some(&1) {
                pack.extend_from_slice(&bytes[1..]);
            } else {
                assert_eq!(bytes, b"NAK\n");
            }
        }
    }
    assert_eq!(encoded, output.stdout);
    assert!(pack.starts_with(b"PACK"));
    let mut index = f
        .git(&destination)
        .args(["index-pack", "--stdin", "--strict"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    index.stdin.take().unwrap().write_all(&pack).unwrap();
    assert!(
        index.wait_with_output().unwrap().status.success(),
        "Git rejected reconstructed pack"
    );
    assert_eq!(
        f.run(&destination, &["cat-file", "blob", oid.trim()]),
        original
    );
}
