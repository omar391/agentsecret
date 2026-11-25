//! Bounded, 8-bit-clean Git pkt-line framing for the native transport.
//!
//! Framing does not authorize a request or inspect compressed pack contents.
//! Callers must complete those checks before returning bytes to a guest.
//! Wire specification: https://git-scm.com/docs/gitprotocol-common

use std::fmt::{self, Display, Formatter};
use std::io::{ErrorKind, Read};

pub const MAX_PACKET_BYTES: usize = 65_520;

#[derive(Clone, Eq, PartialEq)]
pub enum Packet {
    Flush,
    Delimiter,
    ResponseEnd,
    Data(Vec<u8>),
}

// Packet contents can carry arbitrary peer data. Diagnostics expose only size.
impl fmt::Debug for Packet {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Flush => f.write_str("Flush"),
            Self::Delimiter => f.write_str("Delimiter"),
            Self::ResponseEnd => f.write_str("ResponseEnd"),
            Self::Data(bytes) => f.debug_struct("Data").field("bytes", &bytes.len()).finish(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GitWireError {
    InvalidLength,
    Truncated,
    ReadFailed,
    TooLarge,
    Terminal,
}

impl Display for GitWireError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidLength => "git_wire_invalid_length",
            Self::Truncated => "git_wire_truncated",
            Self::ReadFailed => "git_wire_read_failed",
            Self::TooLarge => "git_wire_too_large",
            Self::Terminal => "git_wire_terminal",
        })
    }
}
impl std::error::Error for GitWireError {}

pub struct PacketReader<R> {
    input: R,
    limit: usize,
    consumed: usize,
    failed: bool,
    ended: bool,
}

impl<R: Read> PacketReader<R> {
    pub fn new(input: R, limit: usize) -> Self {
        Self {
            input,
            limit,
            consumed: 0,
            failed: false,
            ended: false,
        }
    }

    /// Read one binary packet, preserving all payload bytes and control kinds.
    ///
    /// # Errors
    /// Refuses malformed lengths, partial packets and per-exchange overruns.
    /// Every failure is terminal; subsequent reads cannot resynchronize.
    pub fn read_packet(&mut self) -> Result<Option<Packet>, GitWireError> {
        if self.failed {
            return Err(GitWireError::Terminal);
        }
        if self.ended {
            return Ok(None);
        }
        self.failed = true;
        let result = self.read_inner();
        if result.is_ok() {
            self.failed = false;
        }
        result
    }

    fn read_inner(&mut self) -> Result<Option<Packet>, GitWireError> {
        let mut header = [0u8; 4];
        loop {
            match self.input.read(&mut header[..1]) {
                Ok(0) => {
                    self.ended = true;
                    return Ok(None);
                }
                Ok(_) => break,
                Err(error) if error.kind() == ErrorKind::Interrupted => continue,
                Err(_) => return Err(GitWireError::ReadFailed),
            }
        }
        if self.limit.saturating_sub(self.consumed) < 4 {
            return Err(GitWireError::TooLarge);
        }
        self.input
            .read_exact(&mut header[1..])
            .map_err(read_error)?;
        let mut length = 0usize;
        for byte in header {
            let digit = match byte {
                b'0'..=b'9' => byte - b'0',
                b'a'..=b'f' => byte - b'a' + 10,
                _ => return Err(GitWireError::InvalidLength),
            };
            length = (length << 4) | usize::from(digit);
        }
        let wire_bytes = length.max(4);
        if length > MAX_PACKET_BYTES || wire_bytes > self.limit - self.consumed {
            return Err(GitWireError::TooLarge);
        }
        self.consumed += wire_bytes;
        Ok(Some(match length {
            0 => Packet::Flush,
            1 => Packet::Delimiter,
            2 => Packet::ResponseEnd,
            3 => return Err(GitWireError::InvalidLength),
            _ => {
                let mut bytes = vec![0; length - 4];
                self.input.read_exact(&mut bytes).map_err(read_error)?;
                Packet::Data(bytes)
            }
        }))
    }
}

fn read_error(error: std::io::Error) -> GitWireError {
    if error.kind() == ErrorKind::UnexpectedEof {
        GitWireError::Truncated
    } else {
        GitWireError::ReadFailed
    }
}

/// Append a packet without decoding payload text or altering line endings.
///
/// # Errors
/// Returns `TooLarge` before modifying output if either bound would be exceeded.
pub fn append_packet(
    output: &mut Vec<u8>,
    packet: &Packet,
    limit: usize,
) -> Result<(), GitWireError> {
    let (header, bytes) = match packet {
        Packet::Flush => (String::from("0000"), &[][..]),
        Packet::Delimiter => (String::from("0001"), &[][..]),
        Packet::ResponseEnd => (String::from("0002"), &[][..]),
        Packet::Data(bytes) => {
            if bytes.len() > MAX_PACKET_BYTES - 4 {
                return Err(GitWireError::TooLarge);
            }
            (format!("{:04x}", bytes.len() + 4), bytes.as_slice())
        }
    };
    if header.len() + bytes.len() > limit.saturating_sub(output.len()) {
        return Err(GitWireError::TooLarge);
    }
    output.extend_from_slice(header.as_bytes());
    output.extend_from_slice(bytes);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    struct Fragmented(Cursor<Vec<u8>>);
    impl Read for Fragmented {
        fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
            let len = out.len().min(1);
            self.0.read(&mut out[..len])
        }
    }

    #[test]
    fn fragmented_binary_payload_and_control_packets_remain_distinct() {
        let packets = [
            Packet::Data((0..=255).collect()),
            Packet::Data(vec![]),
            Packet::Flush,
            Packet::Delimiter,
            Packet::ResponseEnd,
        ];
        let mut wire = Vec::new();
        for packet in &packets {
            append_packet(&mut wire, packet, 4096).unwrap();
        }
        let mut reader = PacketReader::new(Fragmented(Cursor::new(wire)), 4096);
        for packet in packets {
            assert_eq!(reader.read_packet().unwrap(), Some(packet));
        }
        assert_eq!(reader.read_packet().unwrap(), None);
        assert_eq!(reader.read_packet().unwrap(), None);
    }

    #[test]
    fn malformed_or_partial_packets_poison_the_stream() {
        for bytes in [b"0003".as_slice(), b"00xz0000", b"00AF", b"0008ab", b"00"] {
            let mut reader = PacketReader::new(Cursor::new(bytes), 4096);
            assert!(reader.read_packet().is_err());
            assert_eq!(reader.read_packet(), Err(GitWireError::Terminal));
        }
    }

    #[test]
    fn bounds_apply_to_each_packet_and_to_the_whole_exchange() {
        let packet = Packet::Data(vec![0; MAX_PACKET_BYTES - 4]);
        let mut wire = Vec::new();
        append_packet(&mut wire, &packet, MAX_PACKET_BYTES).unwrap();
        let prior = wire.clone();
        assert_eq!(
            append_packet(&mut wire, &Packet::Flush, MAX_PACKET_BYTES),
            Err(GitWireError::TooLarge)
        );
        assert_eq!(wire, prior);
        let mut reader = PacketReader::new(Cursor::new(wire), MAX_PACKET_BYTES - 1);
        assert_eq!(reader.read_packet(), Err(GitWireError::TooLarge));
        assert_eq!(
            append_packet(
                &mut vec![],
                &Packet::Data(vec![0; MAX_PACKET_BYTES - 3]),
                usize::MAX
            ),
            Err(GitWireError::TooLarge)
        );
        let mut reader = PacketReader::new(Cursor::new(b"fff10000"), usize::MAX);
        assert_eq!(reader.read_packet(), Err(GitWireError::TooLarge));
        let mut reader = PacketReader::new(Cursor::new(b"00000000"), 4);
        assert_eq!(reader.read_packet().unwrap(), Some(Packet::Flush));
        assert_eq!(reader.read_packet(), Err(GitWireError::TooLarge));
    }

    #[test]
    fn packet_debug_does_not_expose_peer_contents() {
        let packet = Packet::Data(b"synthetic-private-value".to_vec());
        assert!(!format!("{packet:?}").contains("synthetic-private-value"));
    }
}
