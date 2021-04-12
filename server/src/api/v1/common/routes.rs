use crate::config::{Config};
use crate::middlewares::auth::AuthorizationService;
use crate::models::user::{Login, Claims};
use crate::models::response::LoginResponse;
use crate::models::file::{UploadQuery, ShareRecord};
use nanoid::nanoid;
use actix_web::{HttpRequest, HttpResponse, http::HeaderValue, post, web};
use chrono::{DateTime, Duration, Utc};
use jsonwebtoken::{encode, decode, EncodingKey, Header, DecodingKey, Algorithm, Validation};

fn generate_link() -> String {
    let alphabet: [char; 53] = [
        'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j',
        'k', 'm', 'n', 'p', 'q', 'r', 's', 't', 'u', 'w',
        'x', 'y', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
        'J', 'K', 'L', 'M', 'N', 'P', 'Q', 'R', 'S', 'T',
        'U', 'W', 'Z', 'Y', 'Z', '2', '3', '4', '5', '6',
        '7', '8', '9'
    ];
    nanoid!(8, &alphabet)
}

fn extract_jwt(auth: &HeaderValue) -> Option<Claims> {
    let split: Vec<&str> = auth.to_str().unwrap().split("Bearer").collect();
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
            Some(decoded.claims)
        },
        Err(_) => {
            None
        }
    }
}

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
    let config: Config = Config {};
    let var = config.get_env_key("SECRET_KEY");
    let key = var.as_bytes();
    let auth = req.headers().get("Authorization").unwrap();
    let claims = extract_jwt(auth);
    match claims {
        Some(claims) => {
            let date: DateTime<Utc> = Utc::now() + Duration::hours(12);
            let claims = Claims {
                sub: claims.sub.to_string(),
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
        None => {
            HttpResponse::Unauthorized().body("Invalid token.")
        }
    }
}

#[post("/upload")]
async fn upload(_: AuthorizationService, query: web::Query<UploadQuery>, req: HttpRequest) -> HttpResponse {
    let auth = req.headers().get("Authorization").unwrap();
    let claims = extract_jwt(auth);
    let user = match claims {
        Some(claims) => {
            claims.sub
        },
        None => {
            return HttpResponse::Unauthorized().body("Invalid token.");
        }
    };

    let contentType = match req.headers().get("content-type") {
        Some(value) => value.to_str().unwrap(),
        None => {
            return HttpResponse::BadRequest().finish();
        }
    };
    let contentLength: usize = match req.headers().get("content-length") {
        Some(value) => value.to_str().unwrap().parse().unwrap(),
        None => {
            return HttpResponse::BadRequest().finish();
        }
    };

    //ToDo: Implement upload function
    HttpResponse::Ok().body("Developing")
}

pub fn init_routes(cfg: &mut web::ServiceConfig) {
    cfg.service(login);
    cfg.service(session);
    cfg.service(upload);
}