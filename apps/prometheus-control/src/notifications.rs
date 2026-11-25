use std::{env, future::Future, time::Duration};

use anyhow::{anyhow, ensure, Result};
use domain::{CollectionCompleteness, DeltaCounts};
use teloxide::{
    payloads::GetUpdatesSetters,
    prelude::{Bot, Requester},
    requests::Request,
    types::{AllowedUpdate, ChatId},
};
use tokio::sync::mpsc;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Notice {
    WorkerUnavailable,
    WorkerRecovered,
    PassiveDeltas(CollectionCompleteness, DeltaCounts),
}

pub struct NoticeReceivers {
    pub(crate) summaries: mpsc::Receiver<Notice>,
    pub(crate) watchdog: mpsc::Receiver<Notice>,
}

impl Notice {
    fn render(self) -> String {
        match self {
            Self::WorkerUnavailable => "Prometheus worker heartbeat expired".to_owned(),
            Self::WorkerRecovered => "Prometheus worker heartbeat recovered".to_owned(),
            Self::PassiveDeltas(completeness, delta) => {
                let completeness = match completeness {
                    CollectionCompleteness::Complete => "complete",
                    CollectionCompleteness::Partial => "partial",
                };
                format!(
                    "Prometheus passive inventory ({completeness})\nNew {}\nReactivated {}\nScope changes {}\nChanged {}\nAbsent {}",
                    delta.new_assets,
                    delta.reactivated_assets,
                    delta.scope_changes,
                    delta.changed_assets,
                    delta.absent_assets,
                )
            }
        }
    }
}

trait Transport {
    fn notify(&self, notice: Notice) -> impl Future<Output = bool> + Send;
}

struct LocalTransport;

impl Transport for LocalTransport {
    async fn notify(&self, notice: Notice) -> bool {
        eprintln!("{}", notice.render());
        true
    }
}

pub struct Telegram {
    bot: Bot,
    chat_id: ChatId,
}

impl Telegram {
    pub fn from_environment() -> Result<Option<Self>> {
        let token = env::var_os("PROMETHEUS_TELEGRAM_TOKEN");
        let chat_id = env::var_os("PROMETHEUS_TELEGRAM_CHAT_ID");
        let (token, chat_id) = match (token, chat_id) {
            (None, None) => return Ok(None),
            (Some(token), Some(chat_id)) => (token, chat_id),
            _ => {
                return Err(anyhow!(
                    "Telegram requires both its token and notification chat ID"
                ))
            }
        };
        let token = token
            .into_string()
            .map_err(|_| anyhow!("invalid Telegram token"))?;
        ensure!(valid_token(&token), "invalid Telegram token");
        let chat_id = chat_id
            .to_str()
            .and_then(|value| value.parse::<i64>().ok())
            .filter(|id| *id != 0)
            .ok_or_else(|| anyhow!("invalid Telegram notification chat ID"))?;
        let client = reqwest::Client::builder()
            .https_only(true)
            .no_proxy()
            .timeout(Duration::from_secs(40))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|_| anyhow!("could not configure Telegram transport"))?;
        Ok(Some(Self {
            bot: Bot::with_client(token, client),
            chat_id: ChatId(chat_id),
        }))
    }

    pub async fn poll(&self) {
        let mut offset = 0;
        let mut failures = 0;
        loop {
            let result = self
                .bot
                .get_updates()
                .offset(offset)
                .limit(16)
                .timeout(30)
                .allowed_updates([AllowedUpdate::Message])
                .await;
            match result {
                Ok(updates) => {
                    failures = 0;
                    // Acknowledge messages without processing their content or taking an action.
                    if let Some(last) = updates.iter().map(|update| update.id).max() {
                        let Some(next_offset) = i32::try_from(last.0)
                            .ok()
                            .and_then(|value| value.checked_add(1))
                        else {
                            eprintln!("invalid Telegram long polling offset");
                            tokio::time::sleep(Duration::from_secs(60)).await;
                            continue;
                        };
                        offset = next_offset;
                    }
                }
                Err(_) => {
                    failures += 1;
                    if failures == 3 {
                        eprintln!("Telegram long polling failed");
                        tokio::time::sleep(Duration::from_secs(60)).await;
                        failures = 0;
                    } else {
                        tokio::time::sleep(Duration::from_secs(2 * failures)).await;
                    }
                }
            }
        }
    }
}

impl Transport for Telegram {
    async fn notify(&self, notice: Notice) -> bool {
        let request = self.bot.send_message(self.chat_id, notice.render());
        matches!(
            tokio::time::timeout(Duration::from_secs(5), request.send()).await,
            Ok(Ok(_))
        )
    }
}

fn valid_token(token: &str) -> bool {
    token.len() <= 128
        && token.split_once(':').is_some_and(|(id, secret)| {
            !id.is_empty()
                && id.bytes().all(|byte| byte.is_ascii_digit())
                && !secret.is_empty()
                && secret
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        })
}

pub async fn drain_notifications(receivers: NoticeReceivers, telegram: Option<&Telegram>) {
    match telegram {
        Some(telegram) => dispatch_all(receivers, telegram).await,
        None => dispatch_all(receivers, &LocalTransport).await,
    }
}

async fn dispatch_all(receivers: NoticeReceivers, transport: &impl Transport) {
    tokio::join!(
        dispatch(receivers.watchdog, transport),
        dispatch(receivers.summaries, transport),
    );
}

async fn dispatch(mut receiver: mpsc::Receiver<Notice>, transport: &impl Transport) {
    while let Some(notice) = receiver.recv().await {
        if !transport.notify(notice).await {
            eprintln!("notification delivery failed\n{}", notice.render());
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use anyhow::Result;

    use super::*;

    #[derive(Default)]
    struct MockTransport(Mutex<Vec<String>>);

    impl Transport for MockTransport {
        async fn notify(&self, notice: Notice) -> bool {
            let Ok(mut addressed) = self.0.lock() else {
                return false;
            };
            addressed.push(notice.render());
            true
        }
    }

    #[tokio::test]
    async fn dispatch_sends_only_redacted_aggregate_notices() -> Result<()> {
        let (sender, receiver) = mpsc::channel(3);
        sender.try_send(Notice::WorkerUnavailable)?;
        sender.try_send(Notice::WorkerRecovered)?;
        sender.try_send(Notice::PassiveDeltas(
            CollectionCompleteness::Partial,
            DeltaCounts {
                scope_changes: 1,
                ..DeltaCounts::default()
            },
        ))?;
        drop(sender);
        let mock = MockTransport::default();
        dispatch(receiver, &mock).await;
        let messages = mock.0.into_inner().map_err(|_| anyhow!("mock state"))?;
        assert_eq!(messages.len(), 3);
        assert_eq!(messages[0], "Prometheus worker heartbeat expired");
        assert_eq!(messages[1], "Prometheus worker heartbeat recovered");
        assert!(messages[2].contains("Scope changes 1"));
        assert!(messages[2].contains("partial"));
        Ok(())
    }
}
