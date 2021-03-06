use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct UniversalReponse {
    pub result: bool,
    pub msg: String,
}

#[derive(Serialize, Deserialize)]
pub struct LoginResponse {
    pub result: bool,
    pub msg: String,
    pub token: String,
}

#[derive(Serialize, Deserialize)]
pub struct UploadResponse {
    pub result: bool,
    pub msg: String,
    pub link: String,
}

#[derive(Serialize, Deserialize)]
pub struct SecurityResponse {
    pub result: bool,
    pub msg: String,
    pub public_key: String,
}

#[derive(Serialize, Deserialize)]
pub struct ContentResponse {
    pub result: bool,
    pub link: String,
    pub filetype: String,
    pub filename: String,
    pub content_type: String,
    pub content_length: usize,
    pub content: Option<String>,
}
