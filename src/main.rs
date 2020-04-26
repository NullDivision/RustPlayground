use actix_web::{App, HttpServer};
use actix_web_httpauth::middleware::HttpAuthentication;

mod routes;

#[actix_rt::main]
async fn main() -> std::io::Result<()> {
    HttpServer::new(|| App::new()
        .wrap(HttpAuthentication::bearer(|req, _credentials| async { Ok(req) }))
        .configure(routes::router))
        .bind("127.0.0.1:8080")?
        .run()
        .await
}
