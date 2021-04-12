use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct Login {
    pub username: String,
    pub password: String,
}

#[derive(Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    pub role: String,
    pub iat: usize,
    pub exp: usize,
}
