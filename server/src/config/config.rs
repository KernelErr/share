use std::env;
use nanoid::nanoid;
use rsa::{RSAPrivateKey, RSAPublicKey};
use rand::rngs::OsRng;

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

#[derive(Clone)]
pub struct SecurityOptions {
    pub secret_key: String,
    pub public_key: RSAPublicKey,
    pub private_key: RSAPrivateKey,
}

impl SecurityOptions {
    pub fn generate() -> Self {
        let mut rng = OsRng;
        let bit  = 2048;
        let private_key = RSAPrivateKey::new(&mut rng, bit).unwrap();
        let public_key = RSAPublicKey::from(&private_key);
        let secret_key = nanoid!();
        println!("Generated secret key: {}", secret_key);
        Self {
            secret_key: secret_key,
            public_key: public_key,
            private_key: private_key,
        }
    }
}