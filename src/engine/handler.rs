//! Sigma detection event handler.

use std::sync::Arc;

use tokio::sync::mpsc;
use tracing::{debug, info};

use crate::alerts::AlertSink;
use crate::normalizer::Normalizer;
use crate::reload::DetectorStore;
use crate::response::ResponseEngine;
use crate::sensor::{SensorAction, SensorEvent, SensorEventHandler};

/// Target name for engine operational logs.
const TARGET_ENGINE: &str = "engine";

/// Sigma detection handler that normalizes events and checks them against Sigma rules.
pub struct SigmaDetectionHandler {
    /// Normalizer for converting sensor events to the normalized event model.
    pub normalizer: Arc<Normalizer>,
    /// Live detector store (sigma/ioc hot-reloaded atomically).
    pub detectors: Arc<DetectorStore>,
    /// Hash worker channel (optional).
    pub ioc_hash_tx: Option<mpsc::Sender<(String, u32)>>,
    /// ECS NDJSON alert sink.
    pub alert_sink: AlertSink,
    /// Active response engine.
    pub response_engine: ResponseEngine,
}

impl SensorEventHandler for SigmaDetectionHandler {
    fn handle_event(&self, event: &SensorEvent) {
        tracing::trace!(
            target: TARGET_ENGINE,
            category = ?event.category(),
            provider = event.provider,
            action = ?event.action,
            pid = event.pid,
            "Event received"
        );

        match self.normalizer.normalize(event) {
            Some(normalized_event) => {
                tracing::trace!(target: TARGET_ENGINE, "Event normalized successfully");

                if tracing::enabled!(tracing::Level::TRACE) {
                    if let Ok(json) = serde_json::to_string(&normalized_event) {
                        tracing::trace!(target: TARGET_ENGINE, normalized_json = %json, "Normalized event");
                    }
                }

                if let Some(tx) = &self.ioc_hash_tx {
                    if event.category() == crate::models::EventCategory::Process
                        && event.action == SensorAction::Start
                    {
                        if let crate::models::EventFields::ProcessCreation(fields) =
                            &normalized_event.fields
                        {
                            if let Some(image) = fields.image.as_deref() {
                                let pid = fields
                                    .process_id
                                    .as_deref()
                                    .and_then(|value| value.parse::<u32>().ok())
                                    .or(event.pid)
                                    .unwrap_or(0);

                                if let Err(err) = tx.try_send((image.to_string(), pid)) {
                                    debug!(
                                        target: TARGET_ENGINE,
                                        pid = pid,
                                        image = image,
                                        error = %err,
                                        "IOC hash queue full; dropping job"
                                    );
                                }
                            }
                        }
                    }
                }

                let sigma = self.detectors.sigma();
                if let Some(mut alert) = sigma.check_event(&normalized_event) {
                    self.normalizer
                        .enrich_process_context(&mut alert.event, event.pid.unwrap_or(0));

                    info!(
                        target: TARGET_ENGINE,
                        rule = %alert.rule_name,
                        severity = ?alert.severity,
                        category = ?alert.event.category,
                        "Sigma detection triggered"
                    );

                    self.alert_sink.write_alert(&alert);
                    self.response_engine.handle_alert(&alert);
                } else {
                    tracing::trace!(target: TARGET_ENGINE, "No Sigma rule matched this event");
                }

                let ioc_engine = self.detectors.ioc();
                let ioc_matches = ioc_engine.check_event(&normalized_event);
                if !ioc_matches.is_empty() {
                    for ioc_match in ioc_matches {
                        let mut alert =
                            ioc_engine.build_alert_for_match(&ioc_match, &normalized_event);
                        self.normalizer
                            .enrich_process_context(&mut alert.event, event.pid.unwrap_or(0));
                        info!(
                            target: TARGET_ENGINE,
                            rule = %alert.rule_name,
                            severity = ?alert.severity,
                            category = ?alert.event.category,
                            "IOC detection triggered"
                        );
                        self.alert_sink.write_alert(&alert);
                        self.response_engine.handle_alert(&alert);
                    }
                }
            }
            None => {
                if event.category() == crate::models::EventCategory::Process
                    && event.action == SensorAction::Stop
                {
                    tracing::trace!(
                        target: TARGET_ENGINE,
                        "Process stop event processed for cache maintenance"
                    );
                    return;
                }

                debug!(
                    target: TARGET_ENGINE,
                    category = ?event.category(),
                    action = ?event.action,
                    pid = event.pid,
                    "Failed to normalize event"
                );
            }
        }
    }
}
