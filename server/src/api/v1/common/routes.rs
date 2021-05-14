use crate::db::db::genreate_unique_link;
use crate::middlewares::auth::AuthorizationService;
use crate::models::file::{ShareRecord, UploadQuery};
use crate::models::response::{LoginResponse, SecurityResponse};
use crate::models::user::{Claims, Login};
use crate::{
    config::{SecurityOptions, StorageOptions},
    db::db::add_record,
};
use actix_web::{http::HeaderValue, post, get, web, HttpRequest, HttpResponse};
use chrono::{DateTime, Datelike, Duration, Utc};
use futures::prelude::*;
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use rsa::{PublicKeyPemEncoding, pem::{EncodeConfig, LineEnding}};
use rusoto_s3::{DeleteObjectRequest, PutObjectRequest, S3Client, S3};
use rusoto_signature::stream::ByteStream;
use std::lazy::SyncLazy;

fn extract_jwt(auth: &HeaderValue, security_option: &SecurityOptions) -> Option<Claims> {
    let split: Vec<&str> = auth.to_str().unwrap().split("Bearer").collect();
    let token = split[1].trim();
    let config = security_option.clone();
    let var = config.secret_key;
    let key = var.as_bytes();
    let decode = decode::<Claims>(
        token,
        &DecodingKey::from_secret(key),
        &Validation::new(Algorithm::HS256),
    );
    match decode {
        Ok(decoded) => Some(decoded.claims),
        Err(_) => None,
    }
}

#[post("/login")]
async fn login(
    user: web::Json<Login>,
    security_option: web::Data<SecurityOptions>,
) -> HttpResponse {
    let config = security_option.clone();
    let var = config.secret_key.clone();
    let key = var.as_bytes();
    let date: DateTime<Utc> = Utc::now() + Duration::hours(12);

    let claims = Claims {
        sub: user.username.clone(),
        role: "user".into(),
        iat: Utc::now().timestamp() as usize,
        exp: date.timestamp() as usize,
    };
    let token = encode(&Header::default(), &claims, &EncodingKey::from_secret(key)).unwrap();
    HttpResponse::Ok().json(LoginResponse {
        result: true,
        msg: "Successfully logged in.".into(),
        token: token,
    })
}

#[post("/session")]
async fn session(
    _: AuthorizationService,
    req: HttpRequest,
    security_option: web::Data<SecurityOptions>,
) -> HttpResponse {
    let security_option = security_option.clone();
    let config = security_option.get_ref();
    let var = config.secret_key.clone();
    let key = var.as_bytes();
    let auth = req.headers().get("Authorization").unwrap();
    let claims = extract_jwt(auth, config);
    match claims {
        Some(claims) => {
            let date: DateTime<Utc> = Utc::now() + Duration::hours(12);
            let claims = Claims {
                sub: claims.sub.to_string(),
                role: "user".into(),
                iat: Utc::now().timestamp() as usize,
                exp: date.timestamp() as usize,
            };
            let token =
                encode(&Header::default(), &claims, &EncodingKey::from_secret(key)).unwrap();
            HttpResponse::Ok().json(LoginResponse {
                result: true,
                msg: "Refreshed token.".into(),
                token: token,
            })
        }
        None => HttpResponse::Unauthorized().body("Invalid token."),
    }
}

#[get("/security")]
async fn security(security_option: web::Data<SecurityOptions>) -> HttpResponse {
    let security_option = security_option.clone();
    let config = security_option.get_ref();
    let public_key = config.public_key.to_pem_pkcs8_with_config(EncodeConfig {
        line_ending: LineEnding::CRLF,
    }).unwrap();
    HttpResponse::Ok().json(SecurityResponse {
        result: true,
        msg: "Security information secured.".into(),
        public_key: public_key
    })
}

static S3: SyncLazy<(S3Client, String)> = SyncLazy::new(|| {
    let storage_options = StorageOptions::from_env();
    let cred = rusoto_credential::StaticProvider::new_minimal(
        storage_options.access_key.clone(),
        storage_options.secret_access_key.clone(),
    );
    let client = rusoto_core::request::HttpClient::new().unwrap();
    let region = rusoto_signature::Region::Custom {
        name: storage_options.region_name.clone(),
        endpoint: storage_options.region_endpoint.clone(),
    };
    let s3 = S3Client::new_with(client, cred, region);
    (s3, storage_options.public_bucket.clone())
});

#[post("/upload")]
async fn upload(
    _: AuthorizationService,
    mongodb_client: web::Data<mongodb::Client>,
    security_option: web::Data<SecurityOptions>,
    query: web::Query<UploadQuery>,
    req: HttpRequest,
    mut payload: web::Payload,
) -> HttpResponse {
    let security_option = security_option.clone();
    let config = security_option.get_ref();
    let connection_info = req.connection_info();
    let remote_addr = match connection_info.realip_remote_addr() {
        Some(addr) => addr.split(":").next().unwrap(),
        None => connection_info
            .remote_addr()
            .unwrap()
            .split(":")
            .next()
            .unwrap(),
    };
    let ip = match req.headers().get("CF-Connecting-IP") {
        Some(ip) => ip.to_str().unwrap(),
        None => remote_addr,
    };
    let user_agent = match req.headers().get("User-Agent") {
        Some(ua) => ua.to_str().unwrap(),
        None => "None",
    };
    let auth = req.headers().get("Authorization").unwrap();
    let claims = extract_jwt(auth, config);
    let user = match claims {
        Some(claims) => claims.sub,
        None => {
            return HttpResponse::Unauthorized().body("Invalid token.");
        }
    };

    let mut final_type;
    let utc: DateTime<Utc> = Utc::now();
    let date = Utc::today();
    let unique_id = uuid::Uuid::new_v4();
    let expire_time = match query.expiration {
        0 => utc + Duration::days(1),
        1 => utc + Duration::days(3),
        2 => utc + Duration::days(7),
        3 => utc + Duration::days(30),
        4 => utc + Duration::days(365),
        5 => utc + Duration::days(3650),
        _ => utc + Duration::days(1),
    };
    let content_type = match req.headers().get("content-type") {
        Some(value) => value.to_str().unwrap().to_string(),
        None => {
            return HttpResponse::BadRequest().finish();
        }
    };
    let content_length: usize = match req.headers().get("content-length") {
        Some(value) => value.to_str().unwrap().parse().unwrap(),
        None => {
            return HttpResponse::BadRequest().finish();
        }
    };

    match query.filetype.as_ref() {
        "code" => {
            final_type = "code";
            if content_length > 1024 * 1024 * 5 {
                final_type = "file";
            }
            if content_length > 1024 * 1024 * 1024 * 2 {
                return HttpResponse::BadRequest().finish();
            }
        }
        "file" => {
            final_type = "file";
            if content_length > 1024 * 1024 * 1024 * 2 {
                return HttpResponse::BadRequest().finish();
            }
        }
        _ => {
            return HttpResponse::BadRequest().finish();
        }
    }

    if final_type.eq("file") & (query.expiration > 2) {
        return HttpResponse::BadRequest().finish();
    }

    let ct = content_type.clone();
    let (mut tx, rx) = futures::channel::mpsc::unbounded();
    actix_web::rt::spawn(async move {
        let s3_key = format!(
            "{}/{}/{}/{}",
            date.year(),
            date.month(),
            date.day(),
            unique_id
        );
        S3.0.put_object(PutObjectRequest {
            content_type: Some(ct.to_string()),
            key: s3_key,
            body: Some(ByteStream::new(rx.map_err(|err| {
                std::io::Error::new(std::io::ErrorKind::Other, err)
            }))),
            bucket: S3.1.clone(),

            ..Default::default()
        })
        .await
        .unwrap();
    });

    let mut len = 0;
    while let Some(chunk) = payload.next().await {
        tx.send(chunk.map(|bytes| {
            len += bytes.len();
            bytes.to_vec().into()
        }))
        .await
        .unwrap();
        if len > content_length {
            break;
        }
    }
    let _ = tx.close().await;

    if len != content_length {
        let s3_key = format!(
            "{}/{}/{}/{}",
            date.year(),
            date.month(),
            date.day(),
            unique_id
        );
        S3.0.delete_object(DeleteObjectRequest {
            key: s3_key,
            bucket: S3.1.clone(),

            ..Default::default()
        })
        .await
        .unwrap();
    }

    let s3_key = format!(
        "{}/{}/{}/{}",
        date.year(),
        date.month(),
        date.day(),
        unique_id
    );

    let share_record = ShareRecord {
        link: genreate_unique_link(&mongodb_client).await,
        filename: query.filename.clone(),
        filetype: final_type.into(),
        object_key: s3_key,
        content_type: content_type.to_string(),
        content_length: content_length,
        create_time: utc,
        expire_time: expire_time,
        user: user,
        ip: ip.into(),
        user_agent: user_agent.into(),
        visit_times: 0,
        active: true,
        ban: false,
    };

    match add_record(&mongodb_client, &share_record).await {
        true => HttpResponse::Ok().finish(),
        false => HttpResponse::InternalServerError().finish(),
    }
}

pub fn init_routes(cfg: &mut web::ServiceConfig) {
    cfg.service(login);
    cfg.service(session);
    cfg.service(upload);
    cfg.service(security);
}
