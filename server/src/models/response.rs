use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct LoginResponse {
    pub result: bool,
    pub msg: String,
    pub token: String,
}