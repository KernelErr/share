use envfile::EnvFile;
use std::path::Path;

pub struct Config {}

impl Config {
    pub fn get_env_key(&self, key: &str) -> String {
        let env = EnvFile::new(&Path::new("src/config/config.env")).unwrap();
        env.get(key).unwrap().to_string()
    }
}