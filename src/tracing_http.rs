use tower_http::classify::{ServerErrorsAsFailures, SharedClassifier};
use tower_http::trace::{self, TraceLayer};
use tracing::Level;

pub type TracingLayer = TraceLayer<SharedClassifier<ServerErrorsAsFailures>>;
pub fn trace_layer(
    level: Level,
) -> TraceLayer<SharedClassifier<ServerErrorsAsFailures>, MakeSpan, OnRequest> {
    TraceLayer::new_for_http()
        .make_span_with(MakeSpan::new())
        .on_request(OnRequest::new())
        .on_response(trace::DefaultOnResponse::new().level(level))
}

#[derive(Clone, Debug)]
pub struct MakeSpan {}

impl MakeSpan {
    fn new() -> Self {
        MakeSpan {}
    }
}

impl<B> tower_http::trace::MakeSpan<B> for MakeSpan {
    fn make_span(&mut self, request: &http::Request<B>) -> tracing::Span {
        tracing::span!(
            tracing::Level::INFO,
            "request",
            method = %request.method(),
            uri = %request.uri(),
            version = ?request.version(),
            "otel.name" = tracing::field::Empty,

        )
    }
}
#[derive(Clone, Debug)]
pub struct OnRequest {}

impl OnRequest {
    fn new() -> Self {
        OnRequest {}
    }
}

impl<B> tower_http::trace::OnRequest<B> for OnRequest {
    fn on_request(&mut self, request: &http::request::Request<B>, s: &tracing::Span) {
        use opentelemetry::global;
        use tracing_opentelemetry::OpenTelemetrySpanExt;
        let axum_headers = request.headers();
        let maybe_traceparent = axum_headers.get("traceparent");
        let name = format!("{} {}", request.method(), request.uri().path());
        s.record("otel.name", name.clone());
        if let Some(traceparent) = maybe_traceparent {
            let mut hm = std::collections::HashMap::new();
            hm.insert(
                "traceparent".to_string(),
                traceparent.to_str().unwrap().to_string(),
            );
            let parent_context =
                global::get_text_map_propagator(|propagator| propagator.extract(&hm));
            s.set_parent(parent_context.clone());
        }
    }
}
