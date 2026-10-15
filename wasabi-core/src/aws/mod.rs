//! AWS service integrations.
//!
//! All modules are feature-gated to minimize compile times and dependencies:
//!
//! - `s3` (`aws_s3`) - S3 client with ETag-based caching and multipart uploads
//! - `dynamodb` (`aws_dynamodb`) - DynamoDB client with table management and query helpers
//! - `bedrock` (`aws_bedrock`) - Bedrock AI model streaming for SSE responses
//! - `ses` (`aws_ses`) - Outbound mail (text, HTML, attachments) via SES
//!
//! # Environment Variables
//!
//! | Variable | Module | Description |
//! |----------|--------|-------------|
//! | `S3_BUCKET_SUFFIX` | s3 | Suffix for bucket names (e.g., `myapp.example.com`) |
//! | `DYNAMO_TABLE_PREFIX` | dynamodb | Prefix for table names (e.g., `myapp-prod`) |
//! | `MAIL_SES_FROM` | ses | Sender address; mail is disabled if unset |
//!
//! # Usage
//!
//! ```rust,ignore
//! // S3
//! let s3 = S3Client::from_env().await?;
//! s3.put_object(&BucketName::ConstPrefix("data"), "key.json", data).await?;
//!
//! // DynamoDB
//! let dynamo = DynamoClient::from_env().await?;
//! dynamo.put_entity("users", &user)?.send().await?;
//! ```

#[cfg(feature = "aws_bedrock")]
pub mod bedrock;

#[cfg(feature = "aws_dynamodb")]
pub mod dynamodb;

#[cfg(feature = "aws_s3")]
pub mod s3;

#[cfg(feature = "aws_ses")]
pub mod ses;

/// Test utilities for AWS integration tests.
#[cfg(test)]
pub mod test {
    use rand::random;

    /// Generates a unique test run ID for isolating test resources.
    ///
    /// Uses `TEST_RUN_ID` env var if set (for CI), otherwise generates random ID.
    pub fn test_run_id() -> String {
        let unique_id = random::<u32>();
        if let Ok(run) = std::env::var("TEST_RUN_ID") {
            format!("{}-{}", run, unique_id)
        } else {
            format!("{}", unique_id)
        }
    }
}
