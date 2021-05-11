use envfile::EnvFile;
use std::path::Path;
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
pub struct Config {}

impl Config {
    pub fn get_env_key(&self, key: &str) -> String {
        let env = EnvFile::new(&Path::new("src/config/config.env")).unwrap();
        env.get(key).unwrap().to_string()
    }
}