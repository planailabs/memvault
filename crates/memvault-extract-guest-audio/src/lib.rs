//! Audio transcription guest plugin.
//!
//! Decodes audio (symphonia), resamples to 16 kHz mono (rubato), and runs
//! Whisper inference (candle) to produce a transcript with timed segments.
//! Runs sandboxed under Extism on `wasm32-wasip1`. Whisper model files are
//! read from the guest-visible path passed via `model_paths["whisper"]`
//! (a directory containing `config.json`, `tokenizer.json`, and
//! `model.safetensors` — the candle-transformers whisper layout).
//!
//! Audio is processed in 30-second windows: each window is decoded and
//! resampled incrementally, transcribed with greedy decoding, and emitted as
//! one `TranscriptSegment` spanning the window — the full PCM/mel of a long
//! recording is never held in memory at once.

use memvault_extract_abi::{
    ExtractedText, ExtractionHints, ExtractionInput, ExtractionResponse, ExtractorCapability,
    MatchRule, PluginCapabilities, TranscriptSegment,
};

mod mel;
mod pcm;
mod whisper;

use candle_transformers::models::whisper::N_SAMPLES;

pub const EXTRACTOR: &str = "memvault-whisper";

const AUDIO_EXTS: &[&str] = &["mp3", "m4a", "wav", "flac", "ogg", "oga", "opus"];

/// Ignore a trailing partial window shorter than this (0.1 s): whisper
/// produces nothing useful from it and it is usually decoder padding.
const MIN_TAIL_SAMPLES: usize = pcm::TARGET_RATE / 10;

/// Build this plugin's capability declaration.
pub fn plugin_capabilities() -> PluginCapabilities {
    let mut capabilities = vec![ExtractorCapability::extract(
        MatchRule::MimePrefix("audio/".to_string()),
        0,
    )];
    for ext in AUDIO_EXTS {
        capabilities.push(ExtractorCapability::extract(
            MatchRule::Extension(ext.to_string()),
            0,
        ));
    }
    PluginCapabilities {
        id: EXTRACTOR.to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        capabilities,
    }
}

/// Transcribe audio from a raw extraction envelope. Pure logic, natively testable.
pub fn extract_envelope(envelope: &[u8]) -> ExtractionResponse {
    let (input, content) = match memvault_extract_abi::decode_envelope(envelope) {
        Ok(v) => v,
        Err(e) => {
            return ExtractionResponse::Err {
                code: "envelope".to_string(),
                message: format!("invalid envelope: {e}"),
            };
        }
    };
    transcribe(&input, content)
}

fn transcribe(input: &ExtractionInput, content: &[u8]) -> ExtractionResponse {
    // 1. The model must be configured (cheap check, before any decoding).
    let Some(model_dir) = input.hints.model_paths.get("whisper") else {
        return ExtractionResponse::Err {
            code: "config".to_string(),
            message: "whisper model not configured".to_string(),
        };
    };

    // 2. Probe the container/codec before paying for model load.
    let stream = match pcm::AudioStream::open(content, input.extension.as_deref(), &input.mime) {
        Ok(s) => s,
        Err(e) => {
            return ExtractionResponse::Err {
                code: "decode".to_string(),
                message: e,
            };
        }
    };

    // 3. Load (or reuse the cached) model, then run the streaming loop.
    match whisper::with_model(model_dir, |ctx| {
        run_transcription(ctx, stream, &input.hints)
    }) {
        Ok(response) => response,
        Err(e) => ExtractionResponse::Err {
            code: "model".to_string(),
            message: e,
        },
    }
}

/// How the language token is chosen for decoding.
enum LangMode {
    /// Use this token (or none for English-only models) for every window.
    Fixed(Option<u32>),
    /// Detect from the first audio window.
    Detect,
}

/// Pick the language strategy from the `language` hint (BCP-47 or "auto").
fn resolve_language(
    ctx: &whisper::WhisperContext,
    hint: Option<&str>,
    warnings: &mut Vec<String>,
) -> LangMode {
    let normalized = hint
        .map(|l| l.trim().to_ascii_lowercase())
        .filter(|l| !l.is_empty());
    let Some(lang) = normalized else {
        return if ctx.multilingual {
            LangMode::Detect
        } else {
            LangMode::Fixed(None)
        };
    };
    if lang == "auto" {
        return if ctx.multilingual {
            LangMode::Detect
        } else {
            LangMode::Fixed(None)
        };
    }
    // BCP-47 → whisper's two-letter primary subtag ("en-US" → "en").
    let primary = lang.split(['-', '_']).next().unwrap_or(&lang);
    if !ctx.multilingual {
        if primary != "en" {
            warnings.push(format!(
                "language hint '{lang}' ignored: model is English-only"
            ));
        }
        return LangMode::Fixed(None);
    }
    match ctx.language_token(primary) {
        Some(token) => LangMode::Fixed(Some(token)),
        None => {
            warnings.push(format!(
                "language hint '{lang}' not supported by model; detecting instead"
            ));
            LangMode::Detect
        }
    }
}

/// Append one segment's text to the transcript, recording its UTF-8 byte
/// span. Segments are separated by a single newline.
fn append_segment(
    text: &mut String,
    segments: &mut Vec<TranscriptSegment>,
    seg_text: &str,
    start_ms: u64,
    end_ms: u64,
) {
    let seg_text = seg_text.trim();
    if seg_text.is_empty() {
        return;
    }
    if !text.is_empty() {
        text.push('\n');
    }
    let start = text.len() as u32;
    text.push_str(seg_text);
    let end = text.len() as u32;
    segments.push(TranscriptSegment {
        start_ms,
        end_ms,
        byte_span: (start, end),
    });
}

fn samples_to_ms(samples: u64) -> u64 {
    samples * 1000 / pcm::TARGET_RATE as u64
}

fn run_transcription(
    ctx: &mut whisper::WhisperContext,
    mut stream: pcm::AudioStream,
    hints: &ExtractionHints,
) -> ExtractionResponse {
    let mut text = String::new();
    let mut segments: Vec<TranscriptSegment> = Vec::new();
    let mut warnings: Vec<String> = Vec::new();

    let mut lang_mode = resolve_language(ctx, hints.language.as_deref(), &mut warnings);

    // One 30 s window of 16 kHz mono samples, filled incrementally.
    let mut pcm_buf: Vec<f32> = Vec::with_capacity(N_SAMPLES);
    let mut windowed: u64 = 0; // samples already emitted as windows
    let mut received: u64 = 0; // total samples decoded
    let mut truncated = false;

    // Transcribe one window. `real_len` is the number of non-padding samples.
    let process_window = |ctx: &mut whisper::WhisperContext,
                          window: &[f32],
                          real_len: usize,
                          start_sample: u64,
                          lang_mode: &mut LangMode,
                          text: &mut String,
                          segments: &mut Vec<TranscriptSegment>,
                          warnings: &mut Vec<String>|
     -> Result<(), String> {
        let features = ctx.encode_window(window)?;
        if let LangMode::Detect = lang_mode {
            let token = ctx.detect_language(&features)?;
            let shown = ctx
                .token_text(token)
                .unwrap_or_else(|| format!("token {token}"));
            warnings.push(format!("detected language {shown}"));
            *lang_mode = LangMode::Fixed(Some(token));
        }
        let language_token = match lang_mode {
            LangMode::Fixed(t) => *t,
            LangMode::Detect => None, // unreachable: resolved above
        };
        let decoded = ctx.decode_window(&features, language_token)?;
        if decoded.is_no_speech() {
            return Ok(());
        }
        let start_ms = samples_to_ms(start_sample);
        let end_ms = samples_to_ms(start_sample + real_len as u64);
        append_segment(text, segments, &decoded.text, start_ms, end_ms);
        Ok(())
    };

    let inference_err = |message: String| ExtractionResponse::Err {
        code: "inference".to_string(),
        message,
    };

    'outer: loop {
        let chunk = match stream.next_chunk() {
            Ok(Some(chunk)) => chunk,
            Ok(None) => break,
            Err(e) => {
                return ExtractionResponse::Err {
                    code: "decode".to_string(),
                    message: e,
                };
            }
        };
        received += chunk.len() as u64;
        pcm_buf.extend_from_slice(&chunk);
        while pcm_buf.len() >= N_SAMPLES {
            let window: Vec<f32> = pcm_buf[..N_SAMPLES].to_vec();
            pcm_buf.drain(..N_SAMPLES);
            if let Err(e) = process_window(
                ctx,
                &window,
                N_SAMPLES,
                windowed,
                &mut lang_mode,
                &mut text,
                &mut segments,
                &mut warnings,
            ) {
                return inference_err(e);
            }
            windowed += N_SAMPLES as u64;
            if let Some(max) = hints.max_text_bytes {
                if text.len() >= max {
                    truncated = true;
                    warnings.push(format!(
                        "transcript truncated at {} bytes (max_text_bytes {max})",
                        text.len()
                    ));
                    break 'outer;
                }
            }
        }
    }

    // Trailing partial window, zero-padded to 30 s.
    if !truncated && pcm_buf.len() >= MIN_TAIL_SAMPLES {
        let real_len = pcm_buf.len();
        pcm_buf.resize(N_SAMPLES, 0.0);
        if let Err(e) = process_window(
            ctx,
            &pcm_buf,
            real_len,
            windowed,
            &mut lang_mode,
            &mut text,
            &mut segments,
            &mut warnings,
        ) {
            return inference_err(e);
        }
    }

    if let Some(reason) = stream.abort_reason.take() {
        if received == 0 {
            return ExtractionResponse::Err {
                code: "decode".to_string(),
                message: reason,
            };
        }
        warnings.push(format!("audio stream ended early: {reason}"));
    }
    if stream.skipped_packets > 0 {
        warnings.push(format!(
            "skipped {} undecodable packets",
            stream.skipped_packets
        ));
    }
    if received == 0 {
        warnings.push("no audio samples decoded".to_string());
    }

    ExtractionResponse::Ok(ExtractedText {
        extractor: EXTRACTOR.to_string(),
        extractor_version: env!("CARGO_PKG_VERSION").to_string(),
        text,
        page_breaks: vec![],
        warnings,
        links: vec![],
        segments,
    })
}

#[cfg(target_arch = "wasm32")]
mod wasm {
    use extism_pdk::*;

    #[plugin_fn]
    pub fn capabilities(_input: Vec<u8>) -> FnResult<Vec<u8>> {
        Ok(memvault_extract_abi::encode_capabilities(
            &super::plugin_capabilities(),
        ))
    }

    #[plugin_fn]
    pub fn extract(input: Vec<u8>) -> FnResult<Vec<u8>> {
        let response = super::extract_envelope(&input);
        Ok(memvault_extract_abi::encode_response(&response))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use memvault_extract_abi::{ExtractionHints, ExtractionInput, encode_envelope};

    /// Minimal PCM-16 WAV: 44-byte header + interleaved samples.
    fn wav_bytes(samples: &[i16], channels: u16, rate: u32) -> Vec<u8> {
        let data_len = (samples.len() * 2) as u32;
        let byte_rate = rate * channels as u32 * 2;
        let block_align = channels * 2;
        let mut v = Vec::with_capacity(44 + data_len as usize);
        v.extend_from_slice(b"RIFF");
        v.extend_from_slice(&(36 + data_len).to_le_bytes());
        v.extend_from_slice(b"WAVE");
        v.extend_from_slice(b"fmt ");
        v.extend_from_slice(&16u32.to_le_bytes());
        v.extend_from_slice(&1u16.to_le_bytes()); // PCM
        v.extend_from_slice(&channels.to_le_bytes());
        v.extend_from_slice(&rate.to_le_bytes());
        v.extend_from_slice(&byte_rate.to_le_bytes());
        v.extend_from_slice(&block_align.to_le_bytes());
        v.extend_from_slice(&16u16.to_le_bytes());
        v.extend_from_slice(b"data");
        v.extend_from_slice(&data_len.to_le_bytes());
        for s in samples {
            v.extend_from_slice(&s.to_le_bytes());
        }
        v
    }

    /// Interleaved stereo sine wave (same signal on both channels).
    fn stereo_sine(rate: u32, seconds: f32, freq: f32, amplitude: f32) -> Vec<i16> {
        let frames = (rate as f32 * seconds) as usize;
        let mut out = Vec::with_capacity(frames * 2);
        for i in 0..frames {
            let t = i as f32 / rate as f32;
            let s = (amplitude * (2.0 * std::f32::consts::PI * freq * t).sin() * 32767.0) as i16;
            out.push(s);
            out.push(s);
        }
        out
    }

    fn envelope(content: &[u8], hints: ExtractionHints, mime: &str, ext: &str) -> Vec<u8> {
        let input = ExtractionInput {
            mime: mime.to_string(),
            extension: Some(ext.to_string()),
            hints,
        };
        encode_envelope(&input, content)
    }

    #[test]
    fn capabilities_cover_audio() {
        let caps = plugin_capabilities();
        assert_eq!(caps.id, EXTRACTOR);
        assert!(
            caps.capabilities
                .iter()
                .any(|c| matches!(&c.match_rule, MatchRule::MimePrefix(p) if p == "audio/"))
        );
        for ext in AUDIO_EXTS {
            assert!(
                caps.capabilities
                    .iter()
                    .any(|c| matches!(&c.match_rule, MatchRule::Extension(e) if e == ext))
            );
        }
    }

    // (a) mono mixdown + resample math on a synthetic sine wave.
    #[test]
    fn mixdown_averages_channels() {
        let interleaved = [1.0, 0.0, 0.5, 0.5, -1.0, 1.0];
        assert_eq!(pcm::mixdown(&interleaved, 2), vec![0.5, 0.5, 0.0]);
        assert_eq!(pcm::mixdown(&[0.25, 0.75], 1), vec![0.25, 0.75]);
    }

    #[test]
    fn decode_and_resample_sine_wave() {
        let rate = 44_100u32;
        let seconds = 0.5f32;
        let wav = wav_bytes(&stereo_sine(rate, seconds, 440.0, 0.8), 2, rate);
        let mut stream = pcm::AudioStream::open(&wav, Some("wav"), "audio/wav").unwrap();
        let mut samples = Vec::new();
        while let Some(chunk) = stream.next_chunk().unwrap() {
            samples.extend(chunk);
        }
        assert!(stream.abort_reason.is_none());

        // Output length tracks the rate ratio (FFT resampler adds a small
        // delay/flush wobble at the edges).
        let expected = (rate as f32 * seconds * pcm::TARGET_RATE as f32 / rate as f32) as i64;
        let got = samples.len() as i64;
        assert!(
            (got - expected).abs() < 1500,
            "expected ~{expected} samples at 16 kHz, got {got}"
        );
        assert!(
            samples.iter().all(|s| s.is_finite()),
            "resampled output contains NaN/inf"
        );
        // The sine survives the mixdown + resample with real energy.
        let peak = samples.iter().fold(0f32, |m, s| m.max(s.abs()));
        assert!(peak > 0.4, "expected sine energy, peak was {peak}");
    }

    #[test]
    fn resample_passthrough_at_16k() {
        let mut rs = pcm::Resampler16k::new(pcm::TARGET_RATE).unwrap();
        let out = rs.push(vec![0.1, 0.2, 0.3]).unwrap();
        assert_eq!(out, vec![0.1, 0.2, 0.3]);
        assert!(rs.finish().unwrap().is_empty());
    }

    // (b) byte_span bookkeeping with multi-byte UTF-8 text.
    #[test]
    fn byte_spans_accumulate_correctly() {
        let mut text = String::new();
        let mut segments = Vec::new();
        append_segment(&mut text, &mut segments, "  héllo wörld  ", 0, 30_000);
        append_segment(&mut text, &mut segments, "", 30_000, 60_000); // dropped
        append_segment(&mut text, &mut segments, "日本語のテスト", 30_000, 60_000);
        append_segment(&mut text, &mut segments, "plain", 60_000, 61_500);

        assert_eq!(text, "héllo wörld\n日本語のテスト\nplain");
        assert_eq!(segments.len(), 3);
        for (seg, expected) in segments
            .iter()
            .zip(["héllo wörld", "日本語のテスト", "plain"])
        {
            let (s, e) = seg.byte_span;
            assert_eq!(&text[s as usize..e as usize], expected);
        }
        assert_eq!(segments[0].start_ms, 0);
        assert_eq!(segments[1].end_ms, 60_000);
        assert_eq!(segments[2].end_ms, 61_500);
    }

    // (c) missing model_paths → Err code "config".
    #[test]
    fn missing_model_config_errors() {
        let wav = wav_bytes(&stereo_sine(16_000, 0.2, 440.0, 0.5), 2, 16_000);
        let env = envelope(&wav, ExtractionHints::default(), "audio/wav", "wav");
        match extract_envelope(&env) {
            ExtractionResponse::Err { code, message } => {
                assert_eq!(code, "config");
                assert_eq!(message, "whisper model not configured");
            }
            ExtractionResponse::Ok(_) => panic!("expected config error"),
        }
    }

    // (d) undecodable bytes → Err code "decode".
    #[test]
    fn undecodable_bytes_error() {
        let mut hints = ExtractionHints::default();
        hints
            .model_paths
            .insert("whisper".to_string(), "/nonexistent/whisper".to_string());
        let garbage = vec![0x11u8; 512];
        let env = envelope(&garbage, hints, "audio/wav", "wav");
        match extract_envelope(&env) {
            ExtractionResponse::Err { code, .. } => assert_eq!(code, "decode"),
            ExtractionResponse::Ok(_) => panic!("expected decode error"),
        }
    }

    // Missing model files (but decodable audio) → Err code "model".
    #[test]
    fn missing_model_files_error() {
        let mut hints = ExtractionHints::default();
        hints
            .model_paths
            .insert("whisper".to_string(), "/nonexistent/whisper".to_string());
        let wav = wav_bytes(&stereo_sine(16_000, 0.2, 440.0, 0.5), 2, 16_000);
        let env = envelope(&wav, hints, "audio/wav", "wav");
        match extract_envelope(&env) {
            ExtractionResponse::Err { code, message } => {
                assert_eq!(code, "model");
                assert!(
                    message.contains("config.json"),
                    "unexpected message: {message}"
                );
            }
            ExtractionResponse::Ok(_) => panic!("expected model error"),
        }
    }

    /// End-to-end with a real model, gated on MEMVAULT_TEST_MODELS_DIR.
    /// The dir may either be a whisper model dir itself (contains
    /// config.json) or a parent with model subdirectories.
    #[test]
    fn e2e_transcribes_tone_with_real_model() {
        let Ok(dir) = std::env::var("MEMVAULT_TEST_MODELS_DIR") else {
            eprintln!("MEMVAULT_TEST_MODELS_DIR not set; skipping e2e test");
            return;
        };
        let model_dir = if std::path::Path::new(&dir).join("config.json").exists() {
            dir
        } else {
            let found = std::fs::read_dir(&dir)
                .ok()
                .and_then(|entries| {
                    entries
                        .flatten()
                        .map(|e| e.path())
                        .find(|p| p.join("config.json").exists())
                })
                .map(|p| p.to_string_lossy().into_owned());
            match found {
                Some(d) => d,
                None => panic!("no whisper model dir (with config.json) under {dir}"),
            }
        };

        // 1.5 s of a quiet 440 Hz tone — whisper should return empty-ish
        // text; we only assert the pipeline produces Ok.
        let wav = wav_bytes(&stereo_sine(16_000, 1.5, 440.0, 0.1), 2, 16_000);
        let mut hints = ExtractionHints::default();
        hints.model_paths.insert("whisper".to_string(), model_dir);
        hints.language = Some("en".to_string());
        let env = envelope(&wav, hints, "audio/wav", "wav");
        match extract_envelope(&env) {
            ExtractionResponse::Ok(out) => {
                eprintln!(
                    "e2e transcript: {:?} segments={:?} warnings={:?}",
                    out.text, out.segments, out.warnings
                );
                for seg in &out.segments {
                    let (s, e) = seg.byte_span;
                    assert!(out.text.get(s as usize..e as usize).is_some());
                }
            }
            ExtractionResponse::Err { code, message } => {
                panic!("expected Ok, got {code}: {message}")
            }
        }
    }
}
