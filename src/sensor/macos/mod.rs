//! macOS sensor support.
//!
//! Phase 0 ships a no-op placeholder sensor so the macOS runtime compiles and
//! runs the shared pipeline end to end. Real telemetry lands in later phases:
//! Endpoint Security for process and file events, and `/dev/bpf` capture for
//! network and DNS.

use anyhow::Result;
use tokio::sync::mpsc::Sender;

use super::{Sensor, SensorEvent};

/// Placeholder sensor that emits no events.
///
/// Satisfies the [`Sensor`] contract so the shared runtime can be exercised on
/// macOS before the native telemetry sources exist. It is replaced by the
/// Endpoint Security sensor in Phase 1.
pub struct PlaceholderSensor;

impl PlaceholderSensor {
    pub fn new() -> Self {
        Self
    }
}

impl Default for PlaceholderSensor {
    fn default() -> Self {
        Self::new()
    }
}

impl Sensor for PlaceholderSensor {
    fn start(&self, _tx: Sender<SensorEvent>) -> Result<()> {
        Ok(())
    }

    fn shutdown(&self) {}
}
