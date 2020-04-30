#[macro_use]
extern crate validator_derive;
extern crate validator;
extern crate serde_json;

use actix_web::{App, HttpServer};
use mongodb::{Client, Database};

mod routes;

pub struct AppState {
    db: Database
}

#[actix_rt::main]
async fn main() -> std::io::Result<()> {
    let db = Client::with_uri_str(&"mongodb://localhost:27017/")
        .expect(&"Could not connect to database")
        .database(&"conduit");

    HttpServer::new(move || App::new()
        .data(AppState { db: db.clone() })
        .configure(routes::router))
        .bind("127.0.0.1:8080")?
        .run()
        .await
}
