//! Whisper model loading and greedy decoding via candle.
//!
//! The inference loop is ported from candle's whisper example
//! (candle-examples/examples/whisper and candle-wasm-examples/whisper),
//! restricted to greedy decoding (temperature 0, no fallback) and the
//! safetensors (non-quantized) format. Weights are loaded with
//! `VarBuilder::from_buffered_safetensors` — the mmap path is not available
//! on wasm32-wasip1.

use std::sync::{Mutex, OnceLock};

use candle_core::{D, Device, IndexOp, Tensor};
use candle_nn::VarBuilder;
use candle_nn::ops::softmax;
use candle_transformers::models::whisper::{self as m, Config};
use tokenizers::Tokenizer;

use crate::mel;

/// Skip a window as silence when the no-speech probability exceeds this and
/// the average logprob is below `m::LOGPROB_THRESHOLD` (same heuristic as the
/// candle example).
const NO_SPEECH_THRESHOLD: f64 = m::NO_SPEECH_THRESHOLD;

/// A loaded whisper model with its tokenizer, cached across plugin calls.
pub struct WhisperContext {
    /// Model directory this context was loaded from (cache key).
    pub dir: String,
    model: m::model::Whisper,
    tokenizer: Tokenizer,
    pub config: Config,
    mel_filters: Vec<f32>,
    device: Device,
    suppress_tokens: Tensor,
    sot_token: u32,
    transcribe_token: u32,
    translate_token: u32,
    eot_token: u32,
    no_speech_token: Option<u32>,
    no_timestamps_token: u32,
    /// True when the tokenizer carries language tokens (e.g. `<|en|>`).
    pub multilingual: bool,
}

/// Output of decoding one 30-second window.
pub struct WindowDecode {
    pub text: String,
    pub avg_logprob: f64,
    pub no_speech_prob: f64,
}

impl WindowDecode {
    /// The candle example's silence heuristic.
    pub fn is_no_speech(&self) -> bool {
        self.no_speech_prob > NO_SPEECH_THRESHOLD && self.avg_logprob < m::LOGPROB_THRESHOLD
    }
}

static MODEL_CACHE: OnceLock<Mutex<Option<WhisperContext>>> = OnceLock::new();

/// Run `f` with the cached model for `dir`, (re)loading it if needed. The
/// model persists across calls in the same plugin instance. Load failures
/// are returned as the error string; `f`'s result is passed through.
pub fn with_model<R>(dir: &str, f: impl FnOnce(&mut WhisperContext) -> R) -> Result<R, String> {
    let cell = MODEL_CACHE.get_or_init(|| Mutex::new(None));
    let mut guard = cell.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    let cached = matches!(guard.as_ref(), Some(ctx) if ctx.dir == dir);
    if !cached {
        // Drop any previously cached model before loading the new one so we
        // don't hold two sets of weights at once.
        *guard = None;
        *guard = Some(WhisperContext::load(dir)?);
    }
    Ok(f(guard.as_mut().expect("model loaded above")))
}

fn read_model_file(dir: &str, name: &str) -> Result<Vec<u8>, String> {
    let path = format!("{}/{name}", dir.trim_end_matches('/'));
    std::fs::read(&path).map_err(|e| format!("cannot read {path}: {e}"))
}

fn token_id(tokenizer: &Tokenizer, token: &str) -> Result<u32, String> {
    tokenizer
        .token_to_id(token)
        .ok_or_else(|| format!("tokenizer has no id for {token}"))
}

impl WhisperContext {
    /// Load config.json, tokenizer.json, and model.safetensors from `dir`
    /// (the candle-transformers whisper layout).
    pub fn load(dir: &str) -> Result<Self, String> {
        let device = Device::Cpu;
        let config: Config = serde_json::from_slice(&read_model_file(dir, "config.json")?)
            .map_err(|e| format!("invalid config.json: {e}"))?;
        let tokenizer = Tokenizer::from_bytes(read_model_file(dir, "tokenizer.json")?)
            .map_err(|e| format!("invalid tokenizer.json: {e}"))?;
        let mel_filters = mel::mel_filters(config.num_mel_bins)?;

        let weights = read_model_file(dir, "model.safetensors")?;
        let vb = VarBuilder::from_buffered_safetensors(weights, m::DTYPE, &device)
            .map_err(|e| format!("invalid model.safetensors: {e}"))?;
        let model = m::model::Whisper::load(&vb, config.clone())
            .map_err(|e| format!("failed to load whisper weights: {e}"))?;

        let suppress_tokens: Vec<f32> = (0..config.vocab_size as u32)
            .map(|i| {
                if config.suppress_tokens.contains(&i) {
                    f32::NEG_INFINITY
                } else {
                    0f32
                }
            })
            .collect();
        let suppress_tokens = Tensor::new(suppress_tokens.as_slice(), &device)
            .map_err(|e| format!("failed to build suppress mask: {e}"))?;

        let sot_token = token_id(&tokenizer, m::SOT_TOKEN)?;
        let transcribe_token = token_id(&tokenizer, m::TRANSCRIBE_TOKEN)?;
        let translate_token = token_id(&tokenizer, m::TRANSLATE_TOKEN)?;
        let eot_token = token_id(&tokenizer, m::EOT_TOKEN)?;
        let no_timestamps_token = token_id(&tokenizer, m::NO_TIMESTAMPS_TOKEN)?;
        let no_speech_token = m::NO_SPEECH_TOKENS
            .iter()
            .find_map(|t| tokenizer.token_to_id(t));
        let multilingual = tokenizer.token_to_id("<|en|>").is_some();

        Ok(Self {
            dir: dir.to_string(),
            model,
            tokenizer,
            config,
            mel_filters,
            device,
            suppress_tokens,
            sot_token,
            transcribe_token,
            translate_token,
            eot_token,
            no_speech_token,
            no_timestamps_token,
            multilingual,
        })
    }

    /// Language token for a (lowercased, primary-subtag) language code, e.g.
    /// "de" → id of `<|de|>`. None when the model doesn't know the language.
    pub fn language_token(&self, code: &str) -> Option<u32> {
        self.tokenizer.token_to_id(&format!("<|{code}|>"))
    }

    /// Token id → display form (e.g. `<|de|>`), for warnings.
    pub fn token_text(&self, id: u32) -> Option<String> {
        self.tokenizer.id_to_token(id)
    }

    /// Compute the mel spectrogram for one (zero-padded) 30 s PCM window and
    /// run the audio encoder.
    pub fn encode_window(&mut self, pcm: &[f32]) -> Result<Tensor, String> {
        let n_mels = self.config.num_mel_bins;
        let mel_vec = mel::pcm_to_mel(n_mels, pcm, &self.mel_filters);
        let n_frames = mel_vec.len() / n_mels;
        (|| -> candle_core::Result<Tensor> {
            let mel = Tensor::from_vec(mel_vec, (1, n_mels, n_frames), &self.device)?;
            // The encoder expects exactly N_FRAMES (30 s) of mel input; drop
            // the trailing all-padding frames the spectrogram appends.
            let mel = mel.narrow(2, 0, usize::min(n_frames, m::N_FRAMES))?;
            self.model.encoder.forward(&mel, true)
        })()
        .map_err(|e| format!("encoder failed: {e}"))
    }

    /// Detect the spoken language from encoded audio features: one decoder
    /// step from `<|startoftranscript|>`, argmax restricted to the language
    /// token range (between SOT and `<|translate|>`).
    pub fn detect_language(&mut self, audio_features: &Tensor) -> Result<u32, String> {
        (|| -> candle_core::Result<u32> {
            let tokens = Tensor::new(&[[self.sot_token]], &self.device)?;
            let ys = self.model.decoder.forward(&tokens, audio_features, true)?;
            let logits = self.model.decoder.final_linear(&ys.i(..1)?)?.i(0)?.i(0)?;
            let lang_start = self.sot_token as usize + 1;
            let lang_count = (self.translate_token as usize).saturating_sub(lang_start);
            if lang_count == 0 {
                candle_core::bail!("no language tokens in vocabulary")
            }
            let lang_logits = logits.narrow(0, lang_start, lang_count)?.to_vec1::<f32>()?;
            let best = lang_logits
                .iter()
                .enumerate()
                .max_by(|(_, a), (_, b)| a.total_cmp(b))
                .map(|(i, _)| i)
                .unwrap_or(0);
            Ok((lang_start + best) as u32)
        })()
        .map_err(|e| format!("language detection failed: {e}"))
    }

    /// Greedily decode one window from pre-computed audio features.
    pub fn decode_window(
        &mut self,
        audio_features: &Tensor,
        language_token: Option<u32>,
    ) -> Result<WindowDecode, String> {
        let mut tokens = vec![self.sot_token];
        if let Some(lt) = language_token {
            tokens.push(lt);
        }
        tokens.push(self.transcribe_token);
        tokens.push(self.no_timestamps_token);

        let sample_len = self.config.max_target_positions / 2;
        let mut sum_logprob = 0f64;
        let mut no_speech_prob = f64::NAN;

        let mut step = |tokens: &mut Vec<u32>,
                        i: usize,
                        no_speech_prob: &mut f64,
                        sum_logprob: &mut f64|
         -> candle_core::Result<bool> {
            let tokens_t = Tensor::new(tokens.as_slice(), &self.device)?.unsqueeze(0)?;
            // flush=true on the first step resets the cross-attention KV
            // cache for this window's audio features. Self-attention K/V are
            // recomputed from the full token prefix each step, so feeding
            // the whole sequence is correct (as in the candle example).
            let ys = self
                .model
                .decoder
                .forward(&tokens_t, audio_features, i == 0)?;
            if i == 0 {
                if let Some(ns) = self.no_speech_token {
                    let logits = self.model.decoder.final_linear(&ys.i(..1)?)?.i(0)?.i(0)?;
                    *no_speech_prob =
                        softmax(&logits, 0)?.i(ns as usize)?.to_scalar::<f32>()? as f64;
                }
            }
            let (_, seq_len, _) = ys.dims3()?;
            let logits = self
                .model
                .decoder
                .final_linear(&ys.i((..1, seq_len - 1..))?)?
                .i(0)?
                .i(0)?;
            let logits = logits.broadcast_add(&self.suppress_tokens)?;
            let logits_v: Vec<f32> = logits.to_vec1()?;
            let next_token = logits_v
                .iter()
                .enumerate()
                .max_by(|(_, a), (_, b)| a.total_cmp(b))
                .map(|(i, _)| i as u32)
                .unwrap_or(self.eot_token);
            tokens.push(next_token);
            if next_token == self.eot_token || tokens.len() > self.config.max_target_positions {
                return Ok(true);
            }
            let prob = softmax(&logits, D::Minus1)?
                .i(next_token as usize)?
                .to_scalar::<f32>()? as f64;
            *sum_logprob += prob.ln();
            Ok(false)
        };

        for i in 0..sample_len {
            match step(&mut tokens, i, &mut no_speech_prob, &mut sum_logprob) {
                Ok(true) => break,
                Ok(false) => {}
                Err(e) => return Err(format!("decoder failed: {e}")),
            }
        }

        let text = self
            .tokenizer
            .decode(&tokens, true)
            .map_err(|e| format!("token decoding failed: {e}"))?;
        let avg_logprob = sum_logprob / tokens.len() as f64;
        Ok(WindowDecode {
            text,
            avg_logprob,
            no_speech_prob,
        })
    }
}
