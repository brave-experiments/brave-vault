//! Startup configuration.

/// Header name for the Brave services key (network_constants.h:56).
pub const BRAVE_SERVICE_KEY_HEADER: &str = "BraveServiceKey";

/// Env var carrying the (secret) services key value.
pub const BRAVE_SERVICES_KEY_ENV: &str = "BRAVE_SERVICES_KEY";

/// Brave production sync endpoint (brave_sync BUILD.gn).
pub const SYNC_ENDPOINT: &str = "https://sync-v2.brave.com/v2";

#[derive(Clone)]
pub struct Config {
    pub services_key: String,
    pub endpoint: String,
}

impl Config {
    /// Read config from the environment. Errors clearly if the key is missing.
    pub fn from_env() -> Result<Config, String> {
        let services_key = std::env::var(BRAVE_SERVICES_KEY_ENV).map_err(|_| {
            format!(
                "Missing required env var {BRAVE_SERVICES_KEY_ENV}. \
                 Set it to the Brave services key before launching."
            )
        })?;
        if services_key.trim().is_empty() {
            return Err(format!("{BRAVE_SERVICES_KEY_ENV} is set but empty."));
        }
        let endpoint =
            std::env::var("BRAVE_SYNC_ENDPOINT").unwrap_or_else(|_| SYNC_ENDPOINT.to_string());
        Ok(Config {
            services_key,
            endpoint,
        })
    }
}
