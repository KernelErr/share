use crate::config::SecurityOptions;
use crate::models::user::Claims;
use actix_web::{dev, Error, FromRequest, error::ErrorUnauthorized, HttpRequest};
use futures::future::{err, ok, Ready};
use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};

pub struct AuthorizationService;

impl FromRequest for AuthorizationService {
    type Error = Error;
    type Future = Ready<Result<AuthorizationService, Error>>;
    type Config = ();

    fn from_request(req: &HttpRequest, _payload: &mut dev::Payload) -> Self::Future {
        let auth = req.headers().get("Authorization");
        match auth {
            Some(_) => {
                let split: Vec<&str> = auth.unwrap().to_str().unwrap().split("Bearer").collect();
                let _token = split[1].trim();
                let config = SecurityOptions::from_env();
                let var = config.secret_key;
                let key = var.as_bytes();
                match decode::<Claims>(
                    _token,
                    &DecodingKey::from_secret(key),
                    &Validation::new(Algorithm::HS256),
                ) {
                    Ok(_token) => ok(AuthorizationService),
                    Err(_e) => err(ErrorUnauthorized("Invalid token.")),
                }
            },
            None => err(ErrorUnauthorized("No token found."))
        }
    }
}
