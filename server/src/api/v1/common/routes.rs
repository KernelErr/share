use crate::config::{Config};
use crate::middlewares::auth::AuthorizationService;
use crate::models::user::{Login, Claims};
use crate::models::response::{LoginResponse};
use actix_web::{post, web, HttpResponse, HttpRequest};
use chrono::{DateTime, Duration, Utc};
use jsonwebtoken::{encode, decode, EncodingKey, Header, DecodingKey, Algorithm, Validation};

#[post("/login")]
async fn login(user: web::Json<Login>) -> HttpResponse {
    let config: Config = Config {};
    let var = config.get_env_key("SECRET_KEY");
    let key = var.as_bytes();
    let date: DateTime<Utc> = Utc::now() + Duration::hours(12);

    let claims = Claims {
        sub: user.username.clone(),
        role: "user".into(),
        iat: Utc::now().timestamp() as usize,
        exp: date.timestamp() as usize,
    };
    let token = encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(key),
    ).unwrap();
    HttpResponse::Ok().json(LoginResponse {
        result: true,
        msg: "Successfully logged in.".into(),
        token: token
    })
}

#[post("/session")]
async fn session(_: AuthorizationService, req: HttpRequest) -> HttpResponse {
    let auth = req.headers().get("Authorization");
    let split: Vec<&str> = auth.unwrap().to_str().unwrap().split("Bearer").collect();
    let token = split[1].trim();
    let config: Config = Config {};
    let var = config.get_env_key("SECRET_KEY");
    let key = var.as_bytes();
    let decode = decode::<Claims>(
        token,
        &DecodingKey::from_secret(key),
        &Validation::new(Algorithm::HS256),
    );
    match decode {
        Ok(decoded) => {
            let date: DateTime<Utc> = Utc::now() + Duration::hours(12);
            let claims = Claims {
                sub: decoded.claims.sub.to_string(),
                role: "user".into(),
                iat: Utc::now().timestamp() as usize,
                exp: date.timestamp() as usize,
            };
            let token = encode(
                &Header::default(),
                &claims,
                &EncodingKey::from_secret(key),
            ).unwrap();
            HttpResponse::Ok().json(LoginResponse {
                result: true,
                msg: "Refreshed token.".into(),
                token: token
            })
        },
        Err(_) => {
            HttpResponse::Unauthorized().body("Invalid token.")
        }
    }
}

pub fn init_routes(cfg: &mut web::ServiceConfig) {
    cfg.service(login);
    cfg.service(session);
}