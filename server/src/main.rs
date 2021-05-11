#![feature(once_cell)]
use actix_web::{web, App, HttpServer};

mod config;
mod models;
mod middlewares;
mod api;
use config::DatabaseOptions;
use mongodb::{Client, options::ClientOptions};

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let database_option = DatabaseOptions::from_env();
    let mongodb_string = database_option.connection_string;
    let mongodb_client_options = ClientOptions::parse(&mongodb_string).await.unwrap();
    let mongodb_client = Client::with_options(mongodb_client_options).unwrap();

    HttpServer::new(move || {
        App::new()
        .data(mongodb_client.clone())
        .service(web::scope("/v1").configure(api::v1::common::init_routes))
    })
    .bind("127.0.0.1:8080")?
    .run()
    .await
}