//! Minimal FNV-1a hasher for stable, non-cryptographic identities.

pub(super) struct Fnv64(u64);

impl Fnv64 {
    pub(super) fn new() -> Self {
        Self(0xcbf29ce484222325)
    }
    pub(super) fn bytes(&mut self, bytes: &[u8]) {
        for byte in bytes {
            self.0 ^= u64::from(*byte);
            self.0 = self.0.wrapping_mul(0x100000001b3);
        }
    }
    pub(super) fn u8(&mut self, value: u8) {
        self.bytes(&[value]);
    }
    pub(super) fn i16(&mut self, value: i16) {
        self.bytes(&value.to_le_bytes());
    }
    pub(super) fn u16(&mut self, value: u16) {
        self.bytes(&value.to_le_bytes());
    }
    pub(super) fn i32(&mut self, value: i32) {
        self.bytes(&value.to_le_bytes());
    }
    pub(super) fn u32(&mut self, value: u32) {
        self.bytes(&value.to_le_bytes());
    }
    pub(super) fn u64(&mut self, value: u64) {
        self.bytes(&value.to_le_bytes());
    }
    pub(super) fn string(&mut self, value: &str) {
        self.u64(value.len() as u64);
        self.bytes(value.as_bytes());
    }
    pub(super) fn finish(self) -> u64 {
        self.0
    }
}
