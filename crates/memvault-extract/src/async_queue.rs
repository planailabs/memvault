/// Threshold above which extraction is deferred to background.
pub const ASYNC_THRESHOLD_BYTES: u64 = 50 * 1024 * 1024; // 50 MiB

/// Queue for deferred extraction jobs.
pub struct ExtractionQueue {
    pending: Vec<ExtractionJob>,
}

#[derive(Debug, Clone)]
pub struct ExtractionJob {
    pub manifest_cid: Vec<u8>,
    pub mime_type: String,
    pub content_size: u64,
    pub queued_at_ns: u64,
}

impl ExtractionQueue {
    pub fn new() -> Self {
        Self {
            pending: Vec::new(),
        }
    }

    pub fn enqueue(&mut self, job: ExtractionJob) {
        self.pending.push(job);
    }

    pub fn dequeue(&mut self) -> Option<ExtractionJob> {
        if self.pending.is_empty() {
            None
        } else {
            Some(self.pending.remove(0))
        }
    }

    pub fn pending_count(&self) -> usize {
        self.pending.len()
    }
}

impl Default for ExtractionQueue {
    fn default() -> Self {
        Self::new()
    }
}
