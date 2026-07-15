//! Brave sync HTTP client: authenticated GetUpdates over the Chromium
//! protobuf protocol.

use std::time::{SystemTime, UNIX_EPOCH};

use prost::Message;

use crate::config::{Config, BRAVE_SERVICE_KEY_HEADER};
use crate::crypto::auth::SyncKeys;
use crate::sync::proto;

/// EntitySpecifics field number for passwords (entity_specifics.proto:120).
pub const PASSWORDS_DATA_TYPE_ID: i32 = 45873;
/// EntitySpecifics field number for Nigori (encryption keys). nigori_specifics.proto.
pub const NIGORI_DATA_TYPE_ID: i32 = 47745;
/// EntitySpecifics field number for bookmarks.
pub const BOOKMARKS_DATA_TYPE_ID: i32 = 32904;
/// EntitySpecifics field number for autofill profiles (identities/addresses).
pub const AUTOFILL_PROFILE_DATA_TYPE_ID: i32 = 63951;
/// EntitySpecifics field number for reading list entries.
pub const READING_LIST_DATA_TYPE_ID: i32 = 411028;
/// EntitySpecifics field number for saved tab groups.
pub const SAVED_TAB_GROUP_DATA_TYPE_ID: i32 = 1004874;
/// EntitySpecifics field number for sessions (open tabs).
pub const SESSION_DATA_TYPE_ID: i32 = 50119;
/// EntitySpecifics field number for device info (sync chain devices; never encrypted).
pub const DEVICE_INFO_DATA_TYPE_ID: i32 = 154522;

#[derive(thiserror::Error, Debug)]
pub enum SyncError {
    #[error("http error: {0}")]
    Http(#[from] reqwest::Error),
    #[error("server returned status {0}: {1}")]
    Status(u16, String),
    #[error("protobuf decode failed: {0}")]
    Decode(#[from] prost::DecodeError),
    #[error("sync error_code {0}: {1}")]
    Server(i32, String),
}

pub struct SyncClient {
    http: reqwest::blocking::Client,
    keys: SyncKeys,
    config: Config,
    command_url: String,
}

/// Result of a GetUpdates batch we care about.
#[derive(Default)]
pub struct UpdateBatch {
    pub entries: Vec<proto::SyncEntity>,
    pub encryption_keys: Vec<Vec<u8>>,
    pub new_progress_token: Option<Vec<u8>>,
    pub store_birthday: Option<String>,
    pub changes_remaining: i64,
}

impl SyncClient {
    pub fn new(keys: SyncKeys, config: Config) -> Self {
        let command_url = format!("{}/command/", config.endpoint.trim_end_matches('/'));
        SyncClient {
            http: reqwest::blocking::Client::new(),
            keys,
            config,
            command_url,
        }
    }

    fn timestamp_ms() -> String {
        let ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time after epoch")
            .as_millis();
        ms.to_string()
    }

    fn post(&self, body: Vec<u8>) -> Result<proto::ClientToServerResponse, SyncError> {
        let ts = Self::timestamp_ms();
        let token = self.keys.access_token(&ts);
        let resp = self
            .http
            .post(&self.command_url)
            .header("Content-Type", "application/octet-stream")
            .header("Authorization", format!("Bearer {token}"))
            .header(BRAVE_SERVICE_KEY_HEADER, &self.config.services_key)
            .body(body)
            .send()?;
        let status = resp.status();
        let bytes = resp.bytes()?;
        if !status.is_success() {
            let text = String::from_utf8_lossy(&bytes).into_owned();
            return Err(SyncError::Status(status.as_u16(), text));
        }
        if std::env::var("BRAVE_SYNC_RAW").is_ok() {
            eprintln!(
                "  [raw] response {} bytes: {}",
                bytes.len(),
                hex::encode(&bytes[..bytes.len().min(200)])
            );
        }
        let decoded = proto::ClientToServerResponse::decode(bytes)?;
        if let Some(code) = decoded.error_code {
            if code != 0 {
                return Err(SyncError::Server(
                    code,
                    decoded.error_message.clone().unwrap_or_default(),
                ));
            }
        }
        Ok(decoded)
    }

    /// One GetUpdates request for a single data type.
    pub fn get_updates(
        &self,
        data_type_id: i32,
        progress_token: Option<Vec<u8>>,
        store_birthday: Option<String>,
        need_encryption_key: bool,
    ) -> Result<UpdateBatch, SyncError> {
        let marker = proto::DataTypeProgressMarker {
            data_type_id: Some(data_type_id),
            token: progress_token,
        };
        // GetUpdatesOrigin: PERIODIC=4, NEW_CLIENT=9, RECONFIGURATION=10,
        // GU_TRIGGER=12. Overridable for debugging via BRAVE_GU_ORIGIN /
        // BRAVE_GU_SOURCE.
        //
        // Default to GU_TRIGGER (normal mode), NOT NEW_CLIENT: the go-sync
        // server runs its "count all devices, throttle the chain at 50" gate
        // ONLY on NEW_CLIENT GetUpdates. Sending NEW_CLIENT on every request
        // (as we used to) makes the server treat each ordinary sync as a fresh
        // client joining, so a chain at the device cap throttles all our reads
        // and even the fetch inside delete_device — devices stop refreshing and
        // deletes fail. We derive keys from the mnemonic passphrase, so we never
        // needed the NEW_CLIENT-only server keystore keys anyway.
        let origin: i32 = std::env::var("BRAVE_GU_ORIGIN")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(12);
        let source: i32 = std::env::var("BRAVE_GU_SOURCE")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(9);
        let get_updates = proto::GetUpdatesMessage {
            caller_info: Some(proto::GetUpdatesCallerInfo {
                source: Some(source),
                notifications_enabled: Some(false),
            }),
            fetch_folders: Some(true),
            from_progress_marker: vec![marker],
            streaming: Some(false),
            need_encryption_key: Some(need_encryption_key),
            get_updates_origin: Some(origin),
            is_retry: Some(false),
            client_contexts: vec![],
        };
        let msg = proto::ClientToServerMessage {
            share: String::new(),
            protocol_version: Some(99),
            message_contents: proto::client_to_server_message::Contents::GetUpdates as i32,
            commit: None,
            get_updates: Some(get_updates),
            store_birthday,
            bag_of_chips: None,
            api_key: None,
        };
        let resp = self.post(msg.encode_to_vec())?;
        let gu = resp.get_updates.unwrap_or_default();
        let new_token = gu
            .new_progress_marker
            .iter()
            .find(|m| m.data_type_id == Some(data_type_id))
            .and_then(|m| m.token.clone());
        Ok(UpdateBatch {
            entries: gu.entries,
            encryption_keys: gu.encryption_keys,
            new_progress_token: new_token,
            store_birthday: resp.store_birthday,
            changes_remaining: gu.changes_remaining.unwrap_or(0),
        })
    }

    /// Fetch all entities of a data type, paging by progress token until a
    /// poll returns zero entries or the token stops advancing.
    ///
    /// Chromium's server returns permanent/root nodes on the first request
    /// (often with changes_remaining=0) and the real entities on subsequent
    /// polls that echo back the returned progress token. So we page on the
    /// token, NOT on changes_remaining.
    pub fn fetch_all(
        &self,
        data_type_id: i32,
    ) -> Result<(Vec<proto::SyncEntity>, Vec<Vec<u8>>), SyncError> {
        let mut all = Vec::new();
        let mut enc_keys = Vec::new();
        // Start with an empty (present) token, matching Chromium's first-time
        // GetDownloadProgress rather than an absent field.
        let mut token: Option<Vec<u8>> = Some(Vec::new());
        let mut birthday: Option<String> = None;
        let mut first = true;
        let debug = std::env::var("BRAVE_SYNC_DEBUG").is_ok();
        // Safety cap so a misbehaving server can't loop us forever.
        for poll in 0..1000 {
            let batch = self.get_updates(data_type_id, token.clone(), birthday.clone(), first)?;
            if birthday.is_none() {
                birthday = batch.store_birthday.clone();
            }
            if !batch.encryption_keys.is_empty() {
                enc_keys = batch.encryption_keys.clone();
            }
            let got = batch.entries.len();
            all.extend(batch.entries);
            let prev_token = token.clone();
            token = batch.new_progress_token.or(token);
            first = false;
            if debug {
                eprintln!(
                    "  [poll {poll}] type={data_type_id} got={got} remaining={} token={} birthday={}",
                    batch.changes_remaining,
                    token.as_ref().map(|t| hex::encode(t)).unwrap_or_default(),
                    birthday.as_deref().unwrap_or("")
                );
            }
            // Stop only when the token stops changing (server is caught up).
            if token == prev_token {
                break;
            }
        }
        Ok((all, enc_keys))
    }

    /// Convenience wrapper for the passwords data type.
    pub fn fetch_all_passwords(&self) -> Result<(Vec<proto::SyncEntity>, Vec<Vec<u8>>), SyncError> {
        self.fetch_all(PASSWORDS_DATA_TYPE_ID)
    }

    /// Convenience wrapper for the bookmarks data type.
    pub fn fetch_all_bookmarks(&self) -> Result<(Vec<proto::SyncEntity>, Vec<Vec<u8>>), SyncError> {
        self.fetch_all(BOOKMARKS_DATA_TYPE_ID)
    }

    /// Convenience wrapper for the autofill profile (identities) data type.
    pub fn fetch_all_identities(&self) -> Result<(Vec<proto::SyncEntity>, Vec<Vec<u8>>), SyncError> {
        self.fetch_all(AUTOFILL_PROFILE_DATA_TYPE_ID)
    }

    pub fn fetch_all_reading_list(&self) -> Result<(Vec<proto::SyncEntity>, Vec<Vec<u8>>), SyncError> {
        self.fetch_all(READING_LIST_DATA_TYPE_ID)
    }
    pub fn fetch_all_tab_groups(&self) -> Result<(Vec<proto::SyncEntity>, Vec<Vec<u8>>), SyncError> {
        self.fetch_all(SAVED_TAB_GROUP_DATA_TYPE_ID)
    }
    pub fn fetch_all_sessions(&self) -> Result<(Vec<proto::SyncEntity>, Vec<Vec<u8>>), SyncError> {
        self.fetch_all(SESSION_DATA_TYPE_ID)
    }
    pub fn fetch_all_devices(&self) -> Result<(Vec<proto::SyncEntity>, Vec<Vec<u8>>), SyncError> {
        self.fetch_all(DEVICE_INFO_DATA_TYPE_ID)
    }

    /// Fetch the Nigori node (encryption metadata) and the server keystore keys.
    pub fn fetch_nigori(
        &self,
    ) -> Result<(Option<proto::NigoriSpecifics>, Vec<Vec<u8>>), SyncError> {
        let (entries, enc_keys) = self.fetch_all(NIGORI_DATA_TYPE_ID)?;
        let nigori = entries
            .iter()
            .find_map(|e| e.specifics.as_ref().and_then(|s| s.nigori.clone()));
        Ok((nigori, enc_keys))
    }

    /// Fetch the current store birthday (required on commits).
    pub fn fetch_store_birthday(&self) -> Result<Option<String>, SyncError> {
        let batch = self.get_updates(NIGORI_DATA_TYPE_ID, Some(Vec::new()), None, false)?;
        Ok(batch.store_birthday)
    }

    /// Commit a single already-built SyncEntity. Returns the raw response so the
    /// caller can inspect it (we verify success by re-fetching, since prost
    /// can't decode the proto2 `group` in CommitResponse).
    pub fn commit_entity(
        &self,
        entity: proto::SyncEntity,
        store_birthday: String,
        cache_guid: String,
    ) -> Result<(), SyncError> {
        let commit = proto::CommitMessage {
            entries: vec![entity],
            cache_guid: Some(cache_guid),
        };
        let msg = proto::ClientToServerMessage {
            share: String::new(),
            protocol_version: Some(99),
            message_contents: proto::client_to_server_message::Contents::Commit as i32,
            commit: Some(commit),
            get_updates: None,
            store_birthday: Some(store_birthday),
            bag_of_chips: None,
            api_key: None,
        };
        // post() already surfaces top-level error_code; a 2xx + no error_code
        // means the server accepted the commit batch.
        self.post(msg.encode_to_vec())?;
        Ok(())
    }
}
