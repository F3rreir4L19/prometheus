use std::fmt;

use scope_engine::canonicalize_domain;
use serde::{de, Deserialize};

use super::{PassiveInputError, MAX_DOMAIN_INPUT_BYTES};

pub const MAX_PROVIDER_BYTES: usize = 2 * 1024 * 1024;
const MAX_PROVIDER_RECORDS: usize = 20_000;
const MAX_JSON_LINE_BYTES: usize = 4096;

/// Canonical domains from a provider still lack scope authority.
#[derive(Debug, Default)]
pub struct ProviderCandidates {
    pub candidates: Vec<String>,
    pub malformed: usize,
}

impl ProviderCandidates {
    fn push(&mut self, value: &str) -> Result<(), PassiveInputError> {
        if self.candidates.len() + self.malformed >= MAX_PROVIDER_RECORDS {
            return Err(PassiveInputError::RecordLimit);
        }
        if value.len() <= MAX_DOMAIN_INPUT_BYTES {
            if let Some(domain) = canonicalize_domain(value) {
                self.candidates.push(domain);
                return Ok(());
            }
        }
        self.malformed += 1;
        Ok(())
    }
}

#[derive(Deserialize)]
struct SubfinderRecord {
    host: String,
}

/// Read only the `host` field from bounded JSON Lines. Oversized or malformed lines contribute
/// one diagnostic count, so they can't become candidates or prevent parsing subsequent lines.
pub fn parse_subfinder(input: &[u8]) -> Result<ProviderCandidates, PassiveInputError> {
    check_bytes(input)?;
    let mut batch = ProviderCandidates::default();
    let mut lines = input
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty());
    for line in lines.by_ref().take(MAX_PROVIDER_RECORDS) {
        let record = (line.len() <= MAX_JSON_LINE_BYTES)
            .then(|| serde_json::from_slice::<SubfinderRecord>(line).ok())
            .flatten();
        match record {
            Some(record) => batch.push(&record.host)?,
            None => batch.malformed += 1,
        }
    }
    if lines.next().is_some() {
        return Err(PassiveInputError::RecordLimit);
    }
    Ok(batch)
}

#[derive(Deserialize)]
#[serde(untagged)]
enum CertificateRecord {
    WithNames { name_value: String },
    Invalid(de::IgnoredAny),
}

struct CertificateRecords;

impl<'de> de::Visitor<'de> for CertificateRecords {
    type Value = Result<ProviderCandidates, PassiveInputError>;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a Certificate Transparency result array")
    }

    fn visit_seq<A: de::SeqAccess<'de>>(self, mut sequence: A) -> Result<Self::Value, A::Error> {
        let mut batch = ProviderCandidates::default();
        while let Some(record) = sequence.next_element::<CertificateRecord>()? {
            let result = match record {
                CertificateRecord::WithNames { name_value } => {
                    name_value.split('\n').try_for_each(|name| {
                        let name = name.trim_ascii();
                        batch.push(name.strip_prefix("*.").unwrap_or(name))
                    })
                }
                CertificateRecord::Invalid(_) => batch.push(""),
            };
            if let Err(error) = result {
                // Consume the remainder without allocating names, preserving deserializer framing.
                while sequence.next_element::<de::IgnoredAny>()?.is_some() {}
                return Ok(Err(error));
            }
        }
        Ok(Ok(batch))
    }
}

/// Parse the SAN names in `name_value`. A leading CT wildcard describes its canonical base name
/// only. A truncated or otherwise invalid response provides no observations.
pub fn parse_crtsh(input: &[u8]) -> Result<ProviderCandidates, PassiveInputError> {
    use serde::de::Deserializer;

    check_bytes(input)?;
    let mut deserializer = serde_json::Deserializer::from_slice(input);
    let batch = deserializer
        .deserialize_seq(CertificateRecords)
        .map_err(|_| PassiveInputError::InvalidProvider)??;
    deserializer
        .end()
        .map_err(|_| PassiveInputError::InvalidProvider)?;
    Ok(batch)
}

fn check_bytes(input: &[u8]) -> Result<(), PassiveInputError> {
    if input.len() > MAX_PROVIDER_BYTES {
        return Err(PassiveInputError::ByteLimit);
    }
    Ok(())
}
