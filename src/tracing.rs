use tracing::Level;
use tracing_subscriber::filter::LevelFilter;
use tracing_subscriber::prelude::*;
use tracing_subscriber::registry;

use crate::tracing_json_fmt;

use opentelemetry_sdk::{
    runtime,
    trace::{BatchConfig, RandomIdGenerator, Sampler, Tracer},
};
use tracing_opentelemetry::OpenTelemetryLayer;

pub fn setup(level: Level) {
    let subscriber = registry()
        .with(
            OpenTelemetryLayer::new(init_tracer())
                .with_error_records_to_exceptions(true)
                .with_filter(LevelFilter::from_level(level)),
        )
        .with(
            tracing_subscriber::fmt::layer()
                .json()
                .event_format(tracing_json_fmt::Json)
                .with_filter(LevelFilter::from_level(level)),
        );
    tracing::subscriber::set_global_default(subscriber).expect("Could not setup tracing/logging");
}

// Construct Tracer for OpenTelemetryLayer
fn init_tracer() -> Tracer {
    use opentelemetry_otlp::TonicExporterBuilder;
    let exporter = TonicExporterBuilder::default();
    //let otlp_exporter = opentelemetry_otlp::new_exporter().http();
    opentelemetry_otlp::new_pipeline()
        .tracing()
        .with_trace_config(
            opentelemetry_sdk::trace::Config::default()
                // Customize sampling strategy
                .with_sampler(Sampler::ParentBased(Box::new(Sampler::TraceIdRatioBased(
                    1.0,
                ))))
                // If export trace to AWS X-Ray, you can use XrayIdGenerator
                .with_id_generator(RandomIdGenerator::default()),
        )
        .with_batch_config(BatchConfig::default())
        .with_exporter(exporter)
        .install_batch(runtime::Tokio)
        .unwrap()
}
