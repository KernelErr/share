use std::env;

pub struct StorageOptions {
    pub access_key: String,
    pub secret_access_key: String,
    pub region_name: String,
    pub region_endpoint: String,
    pub public_bucket: String,
}

impl StorageOptions {
    pub fn from_env() -> Self {
        Self {
            access_key: env::var("access_key").unwrap(),
            secret_access_key: env::var("secret_access_key").unwrap(),
            region_name: env::var("region_name").unwrap(),
            region_endpoint: env::var("region_endpoint").unwrap(),
            public_bucket: env::var("public_bucket").unwrap(),
        }
    }
}

pub struct DatabaseOptions {
    pub connection_string: String,
}

impl DatabaseOptions {
    pub fn from_env() -> Self {
        Self {
            connection_string: env::var("connection_string").unwrap(),
        }
    }
}

pub struct SecurityOptions {
    pub secret_key: String,
}

impl SecurityOptions {
    pub fn from_env() -> Self {
        Self {
            secret_key: env::var("secret_key").unwrap(),
        }
    }
}