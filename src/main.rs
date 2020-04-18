use actix_web::{App, HttpResponse, HttpServer, web};

#[actix_rt::main]
async fn main() -> std::io::Result<()> {
    HttpServer::new(
        || App::new().service(web::resource("/").to(|| HttpResponse::Ok()))
    )
        .bind("127.0.0.1:8080")?
        .run()
        .await
}
