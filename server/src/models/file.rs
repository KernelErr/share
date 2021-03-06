use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct UploadQuery {
    pub filename: String,
    pub expiration: u32,
    pub filetype: String,
    pub password: Option<String>,
}

#[derive(Serialize, Deserialize)]
pub struct ShareRecord {
    pub link: String,
    pub filename: String,
    pub filetype: String,
    pub object_key: String,
    pub content_type: String,
    pub content_length: usize,
    pub create_time: DateTime<Utc>,
    pub expire_time: DateTime<Utc>,
    pub password: Option<String>,
    pub user: String,
    pub ip: String,
    pub user_agent: String,
    pub visit_times: u32,
    pub active: bool,
    pub ban: bool,
}

#[derive(Serialize, Deserialize)]
pub struct ContentRecord {
    pub link: String,
    pub filetype: String,
    pub filename: String,
    pub content_type: String,
    pub content_length: usize,
    pub object_key: String,
    pub password: Option<String>,
    pub content: Option<String>,
}

#[derive(Serialize, Deserialize)]
pub struct ContentQuery {
    pub password: Option<String>,
}
