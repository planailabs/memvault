//! Shared top-bar filter state — the bucket / view / show-retracted trio — plus
//! a helper to read all of it reactively inside a `use_server_future` closure
//! and a cross-component invalidation epoch.
//!
//! Usage in a page:
//! ```ignore
//! let filters = use_filters();
//! let res = use_server_future(move || {
//!     let f = filters.read(); // subscribes to bucket/view/retracted + epoch
//!     async move { my_server_fn(f.view, f.bucket, f.show_retracted).await }
//! })?;
//! ```
//! Because `read()` is called *inside* the closure, the resource re-fetches
//! whenever any filter changes or `filters.invalidate()` is called.

use dioxus::prelude::*;

use super::topbar::{ActiveBucketSignal, ActiveViewSignal, ShowRetractedSignal};

/// Monotonic counter bumped to force every filter-dependent resource to
/// re-fetch. A distinct newtype so it doesn't collide with other
/// `Signal<u64>` contexts (Dioxus keys context by type).
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct FilterEpoch(pub u64);
pub type FilterEpochSignal = Signal<FilterEpoch>;

/// A snapshot of the active filters.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Filters {
    pub view: Option<String>,
    pub view_tags: Vec<(String, String)>,
    pub bucket: Option<String>,
    pub show_retracted: bool,
}

/// Handle to the shared filter signals. `Copy`, so it can be moved into a
/// `use_server_future` closure. Obtain via [`use_filters`].
#[derive(Clone, Copy)]
pub struct Filterset {
    view: ActiveViewSignal,
    bucket: ActiveBucketSignal,
    show_retracted: ShowRetractedSignal,
    epoch: FilterEpochSignal,
}

/// Grab the shared filter signals (call in a component body).
pub fn use_filters() -> Filterset {
    Filterset {
        view: use_context(),
        bucket: use_context(),
        show_retracted: use_context(),
        epoch: use_context(),
    }
}

impl Filterset {
    /// Read all filters, subscribing the caller to every one (including the
    /// invalidation epoch). Call this INSIDE a `use_server_future` closure so
    /// the resource re-runs whenever any filter — or `invalidate()` — fires.
    pub fn read(&self) -> Filters {
        let _ = self.epoch.read(); // subscribe to manual invalidation
        let view = self.view.read();
        let filters = Filters {
            view: view.name.clone(),
            view_tags: view.tags.clone(),
            bucket: self.bucket.read().id.clone(),
            show_retracted: self.show_retracted.read().0,
        };
        filters
    }

    /// Bump the epoch so every filter-dependent resource re-fetches. Use after
    /// a write that should be reflected across views.
    pub fn invalidate(&mut self) {
        let next = self.epoch.read().0.wrapping_add(1);
        self.epoch.set(FilterEpoch(next));
    }
}
