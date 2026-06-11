//! Audio decoding (symphonia) and resampling (rubato) to 16 kHz mono f32.
//!
//! `AudioStream` decodes packet-by-packet and yields resampled chunks so the
//! caller can window them incrementally — the full PCM of an hours-long file
//! is never held in memory at once.

use rubato::{FftFixedIn, Resampler};
use symphonia::core::audio::SampleBuffer;
use symphonia::core::codecs::{CODEC_TYPE_NULL, Decoder, DecoderOptions};
use symphonia::core::errors::Error as SymError;
use symphonia::core::formats::{FormatOptions, FormatReader};
use symphonia::core::io::MediaSourceStream;
use symphonia::core::meta::MetadataOptions;
use symphonia::core::probe::Hint;

/// Whisper's expected sample rate.
pub const TARGET_RATE: usize = 16_000;

/// Input frames fed to the FFT resampler per call.
const RESAMPLE_CHUNK: usize = 1024;

/// Average interleaved multi-channel samples down to mono.
pub fn mixdown(interleaved: &[f32], channels: usize) -> Vec<f32> {
    if channels <= 1 {
        return interleaved.to_vec();
    }
    interleaved
        .chunks_exact(channels)
        .map(|frame| frame.iter().sum::<f32>() / channels as f32)
        .collect()
}

/// Streaming resampler from an arbitrary input rate to 16 kHz mono.
pub struct Resampler16k {
    inner: Option<FftFixedIn<f32>>,
    pending: Vec<f32>,
}

impl Resampler16k {
    pub fn new(in_rate: usize) -> Result<Self, String> {
        if in_rate == 0 {
            return Err("source sample rate is 0".to_string());
        }
        let inner = if in_rate == TARGET_RATE {
            None
        } else {
            Some(
                FftFixedIn::<f32>::new(in_rate, TARGET_RATE, RESAMPLE_CHUNK, 2, 1)
                    .map_err(|e| format!("failed to create resampler: {e}"))?,
            )
        };
        Ok(Self { inner, pending: Vec::new() })
    }

    /// Feed mono samples at the source rate; returns whatever 16 kHz output
    /// is ready (possibly empty while the input chunk fills).
    pub fn push(&mut self, samples: Vec<f32>) -> Result<Vec<f32>, String> {
        let Some(rs) = self.inner.as_mut() else {
            return Ok(samples);
        };
        self.pending.extend_from_slice(&samples);
        let mut out = Vec::new();
        let mut consumed = 0;
        loop {
            let need = rs.input_frames_next();
            if self.pending.len() - consumed < need {
                break;
            }
            let chunk = &self.pending[consumed..consumed + need];
            let resampled =
                rs.process(&[chunk], None).map_err(|e| format!("resampling failed: {e}"))?;
            out.extend_from_slice(&resampled[0]);
            consumed += need;
        }
        if consumed > 0 {
            self.pending.drain(..consumed);
        }
        Ok(out)
    }

    /// Flush the remaining buffered input and the resampler's internal delay.
    pub fn finish(&mut self) -> Result<Vec<f32>, String> {
        let Some(rs) = self.inner.as_mut() else {
            return Ok(Vec::new());
        };
        let mut out = Vec::new();
        if !self.pending.is_empty() {
            let pending = std::mem::take(&mut self.pending);
            let resampled = rs
                .process_partial(Some(&[pending.as_slice()]), None)
                .map_err(|e| format!("resampling failed: {e}"))?;
            out.extend_from_slice(&resampled[0]);
        }
        let tail = rs
            .process_partial::<&[f32]>(None, None)
            .map_err(|e| format!("resampling failed: {e}"))?;
        out.extend_from_slice(&tail[0]);
        Ok(out)
    }
}

/// Streaming decoder yielding 16 kHz mono f32 chunks.
pub struct AudioStream {
    format: Box<dyn FormatReader>,
    decoder: Box<dyn Decoder>,
    track_id: u32,
    sample_buf: Option<(SampleBuffer<f32>, symphonia::core::audio::SignalSpec)>,
    resampler: Option<Resampler16k>,
    done: bool,
    /// Packets skipped due to recoverable decode errors.
    pub skipped_packets: u64,
    /// Set when the stream ended on an unexpected error after some output.
    pub abort_reason: Option<String>,
}

impl AudioStream {
    /// Probe the container/codec. Failures here mean undecodable input.
    pub fn open(content: &[u8], extension: Option<&str>, mime: &str) -> Result<Self, String> {
        let mss = MediaSourceStream::new(
            Box::new(std::io::Cursor::new(content.to_vec())),
            Default::default(),
        );
        let mut hint = Hint::new();
        if let Some(ext) = extension {
            hint.with_extension(ext);
        }
        if !mime.is_empty() {
            hint.mime_type(mime);
        }
        let probed = symphonia::default::get_probe()
            .format(&hint, mss, &FormatOptions::default(), &MetadataOptions::default())
            .map_err(|e| format!("unrecognized audio format: {e}"))?;
        let format = probed.format;
        let track = format
            .tracks()
            .iter()
            .find(|t| t.codec_params.codec != CODEC_TYPE_NULL)
            .ok_or_else(|| "no decodable audio track".to_string())?;
        let track_id = track.id;
        let decoder = symphonia::default::get_codecs()
            .make(&track.codec_params, &DecoderOptions::default())
            .map_err(|e| format!("unsupported audio codec: {e}"))?;
        Ok(Self {
            format,
            decoder,
            track_id,
            sample_buf: None,
            resampler: None,
            done: false,
            skipped_packets: 0,
            abort_reason: None,
        })
    }

    /// Next chunk of 16 kHz mono samples; `None` at end of stream. Chunks may
    /// be empty only transiently (never returned — the loop keeps pulling).
    pub fn next_chunk(&mut self) -> Result<Option<Vec<f32>>, String> {
        if self.done {
            return Ok(None);
        }
        loop {
            let packet = match self.format.next_packet() {
                Ok(p) => p,
                // Symphonia signals end-of-stream as an UnexpectedEof I/O
                // error; ResetRequired marks a new stream we don't follow.
                Err(SymError::IoError(_)) | Err(SymError::ResetRequired) => {
                    return self.finish(None);
                }
                Err(e) => return self.finish(Some(format!("stream error: {e}"))),
            };
            if packet.track_id() != self.track_id {
                continue;
            }
            let decoded = match self.decoder.decode(&packet) {
                Ok(d) => d,
                // Recoverable: skip the corrupt packet and continue.
                Err(SymError::DecodeError(_)) | Err(SymError::IoError(_)) => {
                    self.skipped_packets += 1;
                    continue;
                }
                Err(e) => return self.finish(Some(format!("decode error: {e}"))),
            };

            let spec = *decoded.spec();
            let channels = spec.channels.count().max(1);
            let needed = decoded.capacity() * channels;
            let reusable = matches!(
                self.sample_buf.as_ref(),
                Some((b, s)) if *s == spec && b.capacity() >= needed
            );
            if !reusable {
                self.sample_buf =
                    Some((SampleBuffer::<f32>::new(decoded.capacity() as u64, spec), spec));
            }
            let buf = &mut self.sample_buf.as_mut().expect("just set").0;
            buf.copy_interleaved_ref(decoded);
            let mono = mixdown(buf.samples(), channels);

            if self.resampler.is_none() {
                self.resampler = Some(Resampler16k::new(spec.rate as usize)?);
            }
            let out = self.resampler.as_mut().expect("just set").push(mono)?;
            if !out.is_empty() {
                return Ok(Some(out));
            }
        }
    }

    /// Drain the resampler at end-of-stream. A fatal error after partial
    /// output is downgraded to `abort_reason` so the caller can keep the
    /// transcript produced so far (with a warning).
    fn finish(&mut self, abort: Option<String>) -> Result<Option<Vec<f32>>, String> {
        self.done = true;
        self.abort_reason = abort;
        let tail = match self.resampler.as_mut() {
            Some(rs) => rs.finish()?,
            None => Vec::new(),
        };
        if tail.is_empty() { Ok(None) } else { Ok(Some(tail)) }
    }
}
