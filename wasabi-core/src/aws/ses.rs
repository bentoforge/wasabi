//! Outbound mail via AWS SES (v2).
//!
//! A [`Mailer`] sends [`Mail`]s through one of three transports, chosen once at boot:
//!
//! - **SES** - the real thing, used whenever a sender address is configured.
//! - **Log** - writes each mail to the log instead of sending it. For local development, where the
//!   link in a mail matters but an inbox does not.
//! - **Disabled** - drops each mail with a debug line. The default when nothing is configured, so a
//!   sandbox or a developer machine never mails a real customer by accident.
//!
//! # Environment Variables
//!
//! | Variable | Description | Default |
//! |----------|-------------|---------|
//! | `MAIL_TRANSPORT` | `ses`, `log` or `none` | `ses` if `MAIL_SES_FROM` is set, else `none` |
//! | `MAIL_SES_FROM` | Sender, `no-reply@example.com` or `Example <no-reply@example.com>` | (none) |
//! | `MAIL_SES_CONFIGURATION_SET` | SES configuration set to send under | (none) |
//!
//! # Usage
//!
//! ```rust,ignore
//! let mailer = Mailer::from_env().await?;
//!
//! mailer
//!     .send(
//!         Mail::new("customer@example.com", "Your project file", "Hello ...")
//!             .with_html("<p>Hello ...</p>")
//!             .with_reply_to("partner@example.com")
//!             .with_attachment(Attachment::new("label.pdf", "application/pdf", pdf_bytes)),
//!     )
//!     .await?;
//! ```

use anyhow::Context;
use aws_sdk_sesv2::Client;
use aws_sdk_sesv2::error::SdkError;
use aws_sdk_sesv2::primitives::Blob;
use aws_sdk_sesv2::types::{
    AttachmentContentDisposition, Body, Content, Destination, EmailContent, Message, MessageTag,
};
use bytes::Bytes;
use std::env;
use std::fmt::{Display, Formatter};
use std::time::Duration;

/// A single outbound mail.
///
/// Built via [`Mail::new`] and the `with_*` methods, so that new optional parts can be added
/// without breaking callers.
#[derive(Debug, Clone)]
pub struct Mail {
    to: Vec<String>,
    reply_to: Vec<String>,
    subject: String,
    text: String,
    html: Option<String>,
    attachments: Vec<Attachment>,
    tags: Vec<(String, String)>,
}

impl Mail {
    /// Creates a plain text mail to a single recipient.
    pub fn new(to: impl Into<String>, subject: impl Into<String>, text: impl Into<String>) -> Self {
        Mail {
            to: vec![to.into()],
            reply_to: Vec::new(),
            subject: subject.into(),
            text: text.into(),
            html: None,
            attachments: Vec::new(),
            tags: Vec::new(),
        }
    }

    /// Adds another recipient.
    pub fn with_recipient(mut self, to: impl Into<String>) -> Self {
        self.to.push(to.into());
        self
    }

    /// Adds an HTML alternative to the text body.
    ///
    /// The text body is still sent: clients that do not render HTML, and spam filters which
    /// distrust HTML-only mail, read that one.
    pub fn with_html(mut self, html: impl Into<String>) -> Self {
        self.html = Some(html.into());
        self
    }

    /// Adds an address replies should go to instead of the (usually no-reply) sender.
    pub fn with_reply_to(mut self, reply_to: impl Into<String>) -> Self {
        self.reply_to.push(reply_to.into());
        self
    }

    /// Adds an attachment.
    pub fn with_attachment(mut self, attachment: Attachment) -> Self {
        self.attachments.push(attachment);
        self
    }

    /// Adds a message tag, which SES passes on to the event destinations of the configuration set.
    ///
    /// SES only accepts `[A-Za-z0-9_-]` in tag names and values and rejects the **whole send** over
    /// a stray character. A tag is a convenience and a mail is not, so an invalid tag is dropped
    /// (with a debug line) rather than failing the mail.
    pub fn with_tag(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.tags.push((name.into(), value.into()));
        self
    }

    /// The recipients of this mail.
    pub fn to(&self) -> &[String] {
        &self.to
    }

    /// The subject of this mail.
    pub fn subject(&self) -> &str {
        &self.subject
    }

    /// The addresses replies should go to.
    pub fn reply_to(&self) -> &[String] {
        &self.reply_to
    }

    /// The text body of this mail.
    pub fn text(&self) -> &str {
        &self.text
    }

    /// The HTML body of this mail, if any.
    pub fn html(&self) -> Option<&str> {
        self.html.as_deref()
    }
}

/// A file attached to a [`Mail`].
#[derive(Debug, Clone)]
pub struct Attachment {
    file_name: String,
    content_type: String,
    content: Bytes,
    content_id: Option<String>,
}

impl Attachment {
    /// Creates a regular (downloadable) attachment.
    ///
    /// The content type (e.g. `application/pdf`) is given explicitly rather than guessed from the
    /// file name: the caller produced the content and knows what it is.
    pub fn new(
        file_name: impl Into<String>,
        content_type: impl Into<String>,
        content: impl Into<Bytes>,
    ) -> Self {
        Attachment {
            file_name: file_name.into(),
            content_type: content_type.into(),
            content: content.into(),
            content_id: None,
        }
    }

    /// Turns this into an inline attachment, referenced from the HTML body as `cid:{content_id}`.
    pub fn inline(mut self, content_id: impl Into<String>) -> Self {
        self.content_id = Some(content_id.into());
        self
    }
}

/// Sends [`Mail`]s through the transport selected at boot.
pub struct Mailer {
    transport: Transport,
}

enum Transport {
    Ses {
        client: Client,
        from: String,
        configuration_set: Option<String>,
    },
    Log,
    Disabled,
}

impl Mailer {
    /// Selects the transport from the environment (see the module docs).
    ///
    /// # Errors
    ///
    /// Fails if `MAIL_TRANSPORT` is unknown, if it requests `ses` without a `MAIL_SES_FROM`, or if
    /// `MAIL_SES_FROM` is not a sender address. All of these are deployment mistakes which would
    /// otherwise only surface on the first mail.
    pub async fn from_env() -> anyhow::Result<Mailer> {
        let from = non_empty_env("MAIL_SES_FROM");
        let transport = non_empty_env("MAIL_TRANSPORT").map(|t| t.to_ascii_lowercase());

        match (transport.as_deref(), from) {
            (Some("ses") | None, Some(from)) => {
                Mailer::ses(from, non_empty_env("MAIL_SES_CONFIGURATION_SET")).await
            }
            (Some("ses"), None) => {
                anyhow::bail!("MAIL_TRANSPORT is 'ses' but no MAIL_SES_FROM is provided")
            }
            (Some("log"), _) => {
                tracing::warn!("Outbound mail is only written to the log (MAIL_TRANSPORT=log)");
                Ok(Mailer {
                    transport: Transport::Log,
                })
            }
            (Some("none") | None, _) => {
                tracing::info!("Outbound mail is disabled (no MAIL_SES_FROM provided)");
                Ok(Mailer::disabled())
            }
            (Some(other), _) => anyhow::bail!(
                "Unknown MAIL_TRANSPORT '{other}' - expected one of 'ses', 'log' or 'none'"
            ),
        }
    }

    /// Creates a mailer which sends via SES as the given sender.
    ///
    /// # Errors
    ///
    /// Fails if `from` is not a sender address.
    pub async fn ses(from: String, configuration_set: Option<String>) -> anyhow::Result<Mailer> {
        check_from_address(&from)?;

        match &configuration_set {
            Some(name) => {
                tracing::info!("Outbound mail is sent via SES as {from} (configuration set {name})")
            }
            None => tracing::info!("Outbound mail is sent via SES as {from}"),
        }

        // Tight bounds, as a mail is usually sent while a request waits for it. A mail provider
        // having a bad day must surface as a failed send, never as a stalled request handler.
        let timeout_config = aws_config::timeout::TimeoutConfig::builder()
            .connect_timeout(Duration::from_secs(3))
            .operation_attempt_timeout(Duration::from_secs(5))
            .operation_timeout(Duration::from_secs(10))
            .build();
        let config = aws_config::defaults(aws_config::BehaviorVersion::latest())
            .timeout_config(timeout_config)
            .load()
            .await;

        Ok(Mailer {
            transport: Transport::Ses {
                client: Client::new(&config),
                from,
                configuration_set,
            },
        })
    }

    /// Creates a mailer which drops every mail. Useful for tests.
    pub fn disabled() -> Mailer {
        Mailer {
            transport: Transport::Disabled,
        }
    }

    /// Determines if mails are actually delivered (rather than logged or dropped).
    pub fn is_enabled(&self) -> bool {
        matches!(self.transport, Transport::Ses { .. })
    }

    /// Sends the given mail.
    ///
    /// # Errors
    ///
    /// Fails if SES rejects the mail or cannot be reached. Note that a successful send only means
    /// that SES accepted the mail - a bounce is reported asynchronously to the event destinations
    /// of the configuration set (if any).
    #[tracing::instrument(level = "debug", skip_all, fields(to = ?mail.to, subject = %mail.subject), err(level = "debug", Display))]
    pub async fn send(&self, mail: Mail) -> anyhow::Result<()> {
        match &self.transport {
            Transport::Ses {
                client,
                from,
                configuration_set,
            } => send_via_ses(client, from, configuration_set.clone(), mail).await,
            Transport::Log => {
                tracing::info!(
                    "Outbound mail (not sent)\nTo: {}\nReply-To: {}\nSubject: {}\nAttachments: {}\n\n{}",
                    mail.to.join(", "),
                    mail.reply_to.join(", "),
                    mail.subject,
                    mail.attachments
                        .iter()
                        .map(|a| format!(
                            "{} ({}, {} bytes)",
                            a.file_name,
                            a.content_type,
                            a.content.len()
                        ))
                        .collect::<Vec<_>>()
                        .join(", "),
                    mail.text
                );
                Ok(())
            }
            Transport::Disabled => {
                tracing::debug!("Outbound mail is disabled - dropping mail");
                Ok(())
            }
        }
    }
}

async fn send_via_ses(
    client: &Client,
    from: &str,
    configuration_set: Option<String>,
    mail: Mail,
) -> anyhow::Result<()> {
    let mut body = Body::builder().text(utf8(&mail.text)?);
    if let Some(html) = &mail.html {
        body = body.html(utf8(html)?);
    }

    let mut message = Message::builder()
        .subject(utf8(&mail.subject)?)
        .body(body.build());
    for attachment in mail.attachments {
        message = message.attachments(ses_attachment(attachment)?);
    }

    let mut request = client
        .send_email()
        .from_email_address(from)
        .destination(
            Destination::builder()
                .set_to_addresses(Some(mail.to.clone()))
                .build(),
        )
        .set_reply_to_addresses((!mail.reply_to.is_empty()).then_some(mail.reply_to))
        .content(EmailContent::builder().simple(message.build()).build())
        .set_configuration_set_name(configuration_set);
    for (name, value) in &mail.tags {
        if let Some(tag) = tag(name, value) {
            request = request.email_tags(tag);
        }
    }

    let _ = request.send().await.map_err(|err| {
        anyhow::anyhow!(
            "Failed to send mail to {} via SES: {}",
            mail.to.join(", "),
            ServiceMessage(&err)
        )
    })?;

    Ok(())
}

/// Builds one UTF-8 content part.
///
/// The charset is load-bearing rather than decorative: without it SES encodes as 7-bit ASCII and
/// every umlaut in a subject line arrives as a replacement character.
fn utf8(data: &str) -> anyhow::Result<Content> {
    Content::builder()
        .data(data)
        .charset("UTF-8")
        .build()
        .context("Failed to build mail content")
}

fn ses_attachment(attachment: Attachment) -> anyhow::Result<aws_sdk_sesv2::types::Attachment> {
    let disposition = if attachment.content_id.is_some() {
        AttachmentContentDisposition::Inline
    } else {
        AttachmentContentDisposition::Attachment
    };

    aws_sdk_sesv2::types::Attachment::builder()
        .file_name(attachment.file_name)
        .content_type(attachment.content_type)
        .raw_content(Blob::new(attachment.content))
        .content_disposition(disposition)
        .set_content_id(attachment.content_id)
        .build()
        .context("Failed to build mail attachment")
}

/// One message tag, or `None` if SES would reject it (see [`Mail::with_tag`]).
fn tag(name: &str, value: &str) -> Option<MessageTag> {
    if !is_tag_safe(name) || !is_tag_safe(value) {
        tracing::debug!("Dropping SES message tag {name}: not tag-safe");
        return None;
    }

    MessageTag::builder().name(name).value(value).build().ok()
}

fn is_tag_safe(value: &str) -> bool {
    !value.is_empty()
        && value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
}

/// Renders the service's own message for an SDK error, which is the half worth reading. Falls back
/// to the SDK's rendering when the failure never reached the service (a timeout, missing
/// credentials).
struct ServiceMessage<'a, E, R>(&'a SdkError<E, R>);

impl<E: std::error::Error, R: std::fmt::Debug> Display for ServiceMessage<'_, E, R> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self.0.as_service_error() {
            Some(service) => write!(f, "{service}"),
            None => write!(f, "{}", self.0),
        }
    }
}

fn non_empty_env(name: &str) -> Option<String> {
    env::var(name)
        .ok()
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
}

/// Rejects a sender address that cannot be one.
///
/// Only the shape is checked: proving the identity is verified would take `ses:GetEmailIdentity`,
/// which a least-privilege policy granting only `ses:SendEmail` legitimately withholds. What this
/// catches is the paste error - a bare domain, a display name with no address - which otherwise
/// surfaces on the first mail.
fn check_from_address(raw: &str) -> anyhow::Result<()> {
    let complain = |why: &str| {
        anyhow::anyhow!(
            "MAIL_SES_FROM must be a sender address \
             (no-reply@example.com, or 'Example <no-reply@example.com>'), got '{raw}' - {why}"
        )
    };
    let address = match (raw.find('<'), raw.rfind('>')) {
        (Some(open), Some(close)) if close > open => raw
            .get(open + 1..close)
            .ok_or_else(|| complain("the angle brackets do not enclose an address"))?
            .trim(),
        (None, None) => raw,
        _ => return Err(complain("the angle brackets are unbalanced")),
    };

    let (local, domain) = address
        .split_once('@')
        .ok_or_else(|| complain("there is no '@'"))?;
    if local.is_empty() || domain.is_empty() {
        return Err(complain("there is nothing on one side of the '@'"));
    }
    if domain.contains('@') {
        return Err(complain("there is more than one '@'"));
    }
    if !domain.contains('.') {
        return Err(complain("the domain has no dot"));
    }
    if address.chars().any(char::is_whitespace) {
        return Err(complain("the address itself contains whitespace"));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_both_sender_forms() {
        assert!(check_from_address("no-reply@example.com").is_ok());
        assert!(check_from_address("Example <no-reply@example.com>").is_ok());
    }

    #[test]
    fn rejects_malformed_senders() {
        for raw in [
            "example.com",
            "Example",
            "Example <no-reply@example.com",
            "@example.com",
            "no-reply@",
            "no-reply@localhost",
            "no reply@example.com",
            "a@b@example.com",
        ] {
            assert!(check_from_address(raw).is_err(), "accepted '{raw}'");
        }
    }

    #[test]
    fn drops_tags_ses_would_reject() {
        assert!(tag("projectId", "abc_DEF-123").is_some());
        assert!(tag("projectId", "").is_none());
        assert!(tag("projectId", "a.b").is_none());
        assert!(tag("project id", "abc").is_none());
    }

    #[test]
    fn inline_attachments_carry_a_content_id() {
        let attachment =
            ses_attachment(Attachment::new("logo.png", "image/png", vec![1, 2, 3]).inline("logo"))
                .unwrap();
        assert_eq!(
            attachment.content_disposition(),
            Some(&AttachmentContentDisposition::Inline)
        );
        assert_eq!(attachment.content_id(), Some("logo"));

        let attachment =
            ses_attachment(Attachment::new("label.pdf", "application/pdf", vec![1])).unwrap();
        assert_eq!(
            attachment.content_disposition(),
            Some(&AttachmentContentDisposition::Attachment)
        );
        assert_eq!(attachment.content_id(), None);
    }

    #[tokio::test]
    async fn disabled_mailer_drops_mails() {
        let mailer = Mailer::disabled();
        assert!(!mailer.is_enabled());
        assert!(
            mailer
                .send(Mail::new("a@example.com", "s", "t"))
                .await
                .is_ok()
        );
    }
}
