//! Structured metrics on aggregate numeric data. Raw observations and secrets are excluded.

#[derive(Clone, Copy, Debug, Default)]
pub struct Metrics {
    pub dedup_exact_ratio: Option<f64>,
    pub false_merge_rate: Option<f64>,
    pub false_split_rate: Option<f64>,
    pub raw_observations_per_llm_call: Option<f64>,
    pub llm_tokens_per_accepted_candidate: Option<f64>,
}

pub fn record(metrics: Metrics) {
    tracing::info!(
        dedup_exact_ratio = metrics.dedup_exact_ratio,
        false_merge_rate = metrics.false_merge_rate,
        false_split_rate = metrics.false_split_rate,
        raw_observations_per_llm_call = metrics.raw_observations_per_llm_call,
        llm_tokens_per_accepted_candidate = metrics.llm_tokens_per_accepted_candidate,
        "operational metrics"
    );
}
