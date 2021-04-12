use actix_web::{web, App, HttpServer};

mod config;
mod models;
mod middlewares;
mod api;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    HttpServer::new(|| {
        App::new()
            .service(web::scope("/v1").configure(api::v1::common::init_routes))
    })
    .bind("127.0.0.1:8080")?
    .run()
    .await
}