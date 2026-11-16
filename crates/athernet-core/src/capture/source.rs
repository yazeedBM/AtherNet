//! A refilling byte window over any `Read`.
//!
//! This is what keeps memory flat on a 20 GB capture: we hold one buffer, hand
//! out slices into it, and compact-and-refill when a caller needs more bytes
//! than are left. The buffer only ever grows to fit a single oversized record.

use std::io::{self, Read};

pub struct ByteSource<R: Read> {
    inner: R,
    buf: Vec<u8>,
    /// Read cursor inside `buf`.
    pos: usize,
    /// Number of valid bytes in `buf`.
    filled: usize,
    /// Absolute file offset of `buf[0]`.
    base: u64,
    eof: bool,
}

impl<R: Read> ByteSource<R> {
    pub fn new(inner: R, capacity: usize) -> Self {
        Self {
            inner,
            buf: vec![0u8; capacity.max(64 * 1024)],
            pos: 0,
            filled: 0,
            base: 0,
            eof: false,
        }
    }

    /// Absolute offset of the read cursor in the file.
    pub fn offset(&self) -> u64 {
        self.base + self.pos as u64
    }

    pub fn available(&self) -> usize {
        self.filled - self.pos
    }

    /// Make at least `n` bytes readable from the cursor. Returns false at a
    /// clean end of file (fewer than `n` bytes remain).
    pub fn ensure(&mut self, n: usize) -> io::Result<bool> {
        if self.available() >= n {
            return Ok(true);
        }
        if self.pos > 0 {
            self.buf.copy_within(self.pos..self.filled, 0);
            self.base += self.pos as u64;
            self.filled -= self.pos;
            self.pos = 0;
        }
        if self.buf.len() < n {
            let want = n.next_power_of_two().max(self.buf.len() * 2);
            self.buf.resize(want, 0);
        }
        while self.filled < n && !self.eof {
            match self.inner.read(&mut self.buf[self.filled..]) {
                Ok(0) => self.eof = true,
                Ok(read) => self.filled += read,
                Err(ref e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e),
            }
        }
        Ok(self.filled >= n)
    }

    /// Borrow `n` bytes at the cursor. Call `ensure(n)` first.
    pub fn slice(&self, n: usize) -> &[u8] {
        &self.buf[self.pos..self.pos + n]
    }

    pub fn advance(&mut self, n: usize) {
        self.pos = (self.pos + n).min(self.filled);
    }

    /// True once the cursor is at the end of the file with nothing buffered.
    pub fn exhausted(&mut self) -> io::Result<bool> {
        if self.available() > 0 {
            return Ok(false);
        }
        Ok(!self.ensure(1)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refills_and_compacts() {
        let data: Vec<u8> = (0..=255u8).cycle().take(300_000).collect();
        let mut src = ByteSource::new(&data[..], 1024);
        let mut seen = 0usize;
        while src.ensure(7).unwrap() {
            assert_eq!(src.slice(7)[0], data[seen]);
            assert_eq!(src.offset(), seen as u64);
            src.advance(7);
            seen += 7;
        }
        assert_eq!(seen, 300_000 / 7 * 7);
    }

    #[test]
    fn grows_for_an_oversized_record() {
        let data = vec![9u8; 200_000];
        let mut src = ByteSource::new(&data[..], 1024);
        assert!(src.ensure(150_000).unwrap());
        assert_eq!(src.slice(150_000).len(), 150_000);
        src.advance(150_000);
        assert!(!src.ensure(100_000).unwrap());
        assert_eq!(src.available(), 50_000);
    }
}
