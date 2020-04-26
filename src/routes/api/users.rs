use actix_web::{Error, HttpRequest, HttpResponse, FromRequest, dev, web};
use actix_web_httpauth::extractors::AuthExtractor;
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

#[derive(serde::Deserialize, serde::Serialize)]
struct JwtToken {
  user_id: i8
}

fn get_header_map<'a>(req: &'a &HttpRequest) -> &'a actix_web::http::header::HeaderMap {
  req.headers()
}

fn get_auth_header(headers: &actix_web::http::header::HeaderMap) -> &str {
  match headers.get("Authorization") {
    Some(v) => &v.to_str().unwrap()[7..],
    None => ""
  }
}

fn decode_token(auth_header: &str) -> Pin<Box<dyn future::Future<Output = Result<JwtToken, Error>>>> {
  let decode_value = jsonwebtoken::decode::<JwtToken>(
    auth_header,
    &jsonwebtoken::DecodingKey::from_secret(&"secret".as_ref()),
    &jsonwebtoken::Validation::default()
  );

  match decode_value {
    Ok(v) => Box::pin(async move {
      Ok(v.claims)
    }),
    Err(v) => Box::pin(async move {
      println!("{}", v);
      Ok(JwtToken { user_id: 0 })
    })
  }
}

impl FromRequest for JwtToken {
  type Error = Error;
  type Future = Pin<Box<dyn future::Future<Output = Result<JwtToken, Error>>>>;
  type Config = ();

  fn from_request(req: &HttpRequest, _payload: &mut actix_web::dev::Payload) -> Self::Future {
    let auth_header = get_auth_header(get_header_map(&req));

    decode_token(auth_header)
  }
}

pub fn router(cfg: &mut web::ServiceConfig) {
  cfg.service(
    web::resource("/user").route(web::get().to(|token: JwtToken| {
      // users.find_one(Some(doc! { "_id": r. }), None)
      HttpResponse::Ok().json(token)
      // .json(mongodb::Client::with_uri_str("mongodb://localhost:27017/").unwrap()
      // .database("conduit")
      // .collection("users"))
    }))
  );
}
