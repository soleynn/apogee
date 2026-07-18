#![no_main]

use libfuzzer_sys::fuzz_target;

use apogee_zipatch::{
    ApplyOptions, DataSource, Error, KeepFilter, Limits, MAGIC, PatchReader, PatchSink, SafePath,
    TargetPath, apply,
};

// The apply interpreter frames the `F:A` block stream and dispatches every command; boot patches
// arrive over plain HTTP, so it must stay panic-free and allocation-bounded on any bytes. Drive a
// magic-prefixed body (so the fuzzer reaches framing without rediscovering the magic) into a sink
// whose only real work is decoding through the shared codec, exactly as `DiskSink` does but without
// touching disk.
struct MemSink;

impl PatchSink for MemSink {
    fn write(&mut self, _target: &TargetPath, _off: u64, src: DataSource<'_>) -> Result<(), Error> {
        if let DataSource::Deflate {
            bytes,
            decompressed_len,
            ..
        } = src
        {
            let mut out = Vec::new();
            // The codec caps output before decoding, so a hostile size never allocates.
            let _ = apogee_sqpack::codec::inflate(
                bytes,
                &mut out,
                decompressed_len,
                &apogee_sqpack::codec::Limits::default(),
            );
        }
        Ok(())
    }

    fn write_empty_block(&mut self, _t: &TargetPath, _off: u64, _blocks: u32) -> Result<(), Error> {
        Ok(())
    }
    fn truncate(&mut self, _t: &TargetPath, _len: u64) -> Result<(), Error> {
        Ok(())
    }
    fn remove_file(&mut self, _t: &TargetPath) -> Result<(), Error> {
        Ok(())
    }
    fn remove_expansion(&mut self, _exp: u16, _keep: &KeepFilter) -> Result<(), Error> {
        Ok(())
    }
    fn make_dir_tree(&mut self, _rel: &SafePath) -> Result<(), Error> {
        Ok(())
    }
    fn remove_dir(&mut self, _rel: &SafePath) -> Result<(), Error> {
        Ok(())
    }
}

fuzz_target!(|data: &[u8]| {
    let cap = 1usize << 16;
    if data.len() + MAGIC.len() > cap {
        return;
    }
    let mut patch = Vec::with_capacity(MAGIC.len() + data.len());
    patch.extend_from_slice(&MAGIC);
    patch.extend_from_slice(data);

    let limits = Limits {
        max_chunk_size: cap as u32,
    };
    if let Ok(reader) = PatchReader::open(patch.as_slice()) {
        let mut reader = reader.with_limits(limits).verify_crc(false);
        let mut sink = MemSink;
        let _ = apply(&mut reader, &mut sink, &ApplyOptions::default());
    }
});
