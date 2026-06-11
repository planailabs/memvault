pub mod detail;
pub mod explorer;
pub mod pages;

/// 2s delay between media-status polls. cfg-gated async sleep (same idiom
/// as the cmd-k debounce): gloo timer on wasm, tokio on the server.
pub(crate) async fn media_poll_delay() {
    #[cfg(target_arch = "wasm32")]
    {
        gloo_timers::future::TimeoutFuture::new(2000).await;
    }
    #[cfg(all(not(target_arch = "wasm32"), feature = "server"))]
    {
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    }
}
