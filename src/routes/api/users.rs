use actix_web::{Error, HttpRequest, HttpResponse, FromRequest, dev, web};
// use actix_web_httpauth::extractors::AuthExtractor;
use futures::future;
use std::pin::Pin;

// #[derive(serde::Deserialize, serde::Serialize)]
// struct UserToken {}

// enum ServiceError {}

// impl AuthExtractor for UserToken {
//   type Error = Error;
//   type Future = Pin<Box<dyn future::Future<Output = Result<UserToken, Error>>>>;

//   fn from_service_request() {}
// }

pub fn router(cfg: &mut web::ServiceConfig) {
  cfg.service(
    web::resource("/user").route(web::get().to(|user: actix_web_httpauth::extractors::bearer::BearerAuth| {
      // users.find_one(Some(doc! { "_id": r. }), None)
      HttpResponse::Ok().json(user.token())
      // .json(mongodb::Client::with_uri_str("mongodb://localhost:27017/").unwrap()
      // .database("conduit")
      // .collection("users"))
    }))
  );
}
