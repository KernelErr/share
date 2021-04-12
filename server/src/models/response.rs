use serde::{Deserialize, Serialize};

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
    pub link: String
}