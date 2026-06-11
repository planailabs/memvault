//! Whisper log-mel spectrogram, single-threaded.
//!
//! Port of `candle_transformers::models::whisper::audio` (itself adapted from
//! whisper.cpp). The library version parallelizes with `std::thread::scope`,
//! which aborts on `wasm32-wasip1` (no threads under WASI preview 1), so we
//! carry the single-threaded variant candle's own wasm whisper example uses.
//!
//! The mel filterbank coefficients (librosa-compatible, 80 and 128 bins) are
//! embedded the same way candle's whisper examples embed them: as raw
//! little-endian f32 dumps (`melfilters.bytes` / `melfilters128.bytes`,
//! copied from the candle repository).

use candle_transformers::models::whisper as m;

const MEL_FILTERS_80: &[u8] = include_bytes!("melfilters.bytes");
const MEL_FILTERS_128: &[u8] = include_bytes!("melfilters128.bytes");

/// Mel filterbank for the given number of mel bins (80 or 128).
pub fn mel_filters(num_mel_bins: usize) -> Result<Vec<f32>, String> {
    let bytes = match num_mel_bins {
        80 => MEL_FILTERS_80,
        128 => MEL_FILTERS_128,
        n => return Err(format!("unsupported num_mel_bins {n} (expected 80 or 128)")),
    };
    Ok(bytes
        .chunks_exact(4)
        .map(|c| f32::from_le_bytes([c[0], c[1], c[2], c[3]]))
        .collect())
}

/// Log-mel spectrogram of `samples` (16 kHz mono PCM in [-1, 1]).
/// Returns `n_mel * n_len` values laid out mel-major (`mel[j * n_len + i]`).
pub fn pcm_to_mel(num_mel_bins: usize, samples: &[f32], filters: &[f32]) -> Vec<f32> {
    log_mel_spectrogram(samples, filters, m::N_FFT, m::HOP_LENGTH, num_mel_bins)
}

// https://github.com/ggerganov/whisper.cpp/blob/4774d2feb01a772a15de81ffc34b34a1f294f020/whisper.cpp#L2357
fn fft(inp: &[f32]) -> Vec<f32> {
    let n = inp.len();
    if n == 1 {
        return vec![inp[0], 0.0];
    }
    if n % 2 == 1 {
        return dft(inp);
    }
    let mut out = vec![0.0f32; n * 2];

    let mut even = Vec::with_capacity(n / 2);
    let mut odd = Vec::with_capacity(n / 2);
    for (i, &v) in inp.iter().enumerate() {
        if i % 2 == 0 {
            even.push(v)
        } else {
            odd.push(v)
        }
    }

    let even_fft = fft(&even);
    let odd_fft = fft(&odd);

    let two_pi = 2.0 * std::f32::consts::PI;
    let n_t = n as f32;
    for k in 0..n / 2 {
        let theta = two_pi * k as f32 / n_t;
        let re = theta.cos();
        let im = -theta.sin();

        let re_odd = odd_fft[2 * k];
        let im_odd = odd_fft[2 * k + 1];

        out[2 * k] = even_fft[2 * k] + re * re_odd - im * im_odd;
        out[2 * k + 1] = even_fft[2 * k + 1] + re * im_odd + im * re_odd;

        out[2 * (k + n / 2)] = even_fft[2 * k] - re * re_odd + im * im_odd;
        out[2 * (k + n / 2) + 1] = even_fft[2 * k + 1] - re * im_odd - im * re_odd;
    }
    out
}

// https://github.com/ggerganov/whisper.cpp/blob/4774d2feb01a772a15de81ffc34b34a1f294f020/whisper.cpp#L2337
fn dft(inp: &[f32]) -> Vec<f32> {
    let n = inp.len();
    let two_pi = 2.0 * std::f32::consts::PI;

    let mut out = Vec::with_capacity(2 * n);
    let n_t = n as f32;
    for k in 0..n {
        let k_t = k as f32;
        let mut re = 0.0f32;
        let mut im = 0.0f32;
        for (j, &v) in inp.iter().enumerate() {
            let angle = two_pi * k_t * j as f32 / n_t;
            re += v * angle.cos();
            im -= v * angle.sin();
        }
        out.push(re);
        out.push(im);
    }
    out
}

// https://github.com/ggerganov/whisper.cpp/blob/4774d2feb01a772a15de81ffc34b34a1f294f020/whisper.cpp#L2414
fn log_mel_spectrogram_worker(
    hann: &[f32],
    samples: &[f32],
    filters: &[f32],
    fft_size: usize,
    fft_step: usize,
    n_len: usize,
    n_mel: usize,
) -> Vec<f32> {
    let n_fft = 1 + fft_size / 2;
    let mut fft_in = vec![0.0f32; fft_size];
    let mut mel = vec![0.0f32; n_len * n_mel];

    for i in 0..n_len {
        let offset = i * fft_step;

        // Apply the Hann window.
        for j in 0..fft_size {
            fft_in[j] = if offset + j < samples.len() {
                hann[j] * samples[offset + j]
            } else {
                0.0
            }
        }

        // FFT -> mag^2
        let mut fft_out = fft(&fft_in);
        for j in 0..fft_size {
            fft_out[j] = fft_out[2 * j] * fft_out[2 * j] + fft_out[2 * j + 1] * fft_out[2 * j + 1];
        }
        for j in 1..fft_size / 2 {
            let v = fft_out[fft_size - j];
            fft_out[j] += v;
        }

        // Mel spectrogram.
        for j in 0..n_mel {
            let mut sum = 0.0f32;
            for k in 0..n_fft {
                sum += fft_out[k] * filters[j * n_fft + k];
            }
            mel[j * n_len + i] = f32::max(sum, 1e-10).log10();
        }
    }
    mel
}

fn log_mel_spectrogram(
    samples: &[f32],
    filters: &[f32],
    fft_size: usize,
    fft_step: usize,
    n_mel: usize,
) -> Vec<f32> {
    let two_pi = 2.0 * std::f32::consts::PI;
    let hann: Vec<f32> = (0..fft_size)
        .map(|i| 0.5 * (1.0 - (two_pi * i as f32 / fft_size as f32).cos()))
        .collect();
    let n_len = samples.len() / fft_step;

    // Pad audio with at least one extra chunk of zeros.
    let pad = 100 * m::CHUNK_LENGTH / 2;
    let n_len = if n_len % pad != 0 { (n_len / pad + 1) * pad } else { n_len };
    let n_len = n_len + pad;
    let samples = {
        let mut padded = samples.to_vec();
        padded.resize(n_len * fft_step, 0.0);
        padded
    };

    let mut mel =
        log_mel_spectrogram_worker(&hann, &samples, filters, fft_size, fft_step, n_len, n_mel);
    let mmax = mel
        .iter()
        .max_by(|u, v| u.partial_cmp(v).unwrap_or(std::cmp::Ordering::Greater))
        .copied()
        .unwrap_or(0.0)
        - 8.0;
    for v in mel.iter_mut() {
        *v = f32::max(*v, mmax) / 4.0 + 1.0
    }
    mel
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_filters_parse() {
        let f80 = mel_filters(80).unwrap();
        assert_eq!(f80.len(), 80 * (1 + m::N_FFT / 2));
        let f128 = mel_filters(128).unwrap();
        assert_eq!(f128.len(), 128 * (1 + m::N_FFT / 2));
        assert!(f80.iter().all(|v| v.is_finite()));
        assert!(mel_filters(96).is_err());
    }

    #[test]
    fn mel_shape_for_full_window() {
        // A full 30 s window: 3000 content frames padded to 4500 by the
        // extra-chunk rule, mel-major layout.
        let filters = mel_filters(80).unwrap();
        let samples = vec![0.0f32; m::N_SAMPLES];
        let mel = pcm_to_mel(80, &samples, &filters);
        assert_eq!(mel.len() % 80, 0);
        let n_len = mel.len() / 80;
        assert_eq!(n_len, 4500);
        assert!(mel.iter().all(|v| v.is_finite()));
    }
}
