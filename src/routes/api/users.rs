use actix_web::{Error, HttpRequest, HttpResponse, FromRequest, dev, http, web};
use actix_web_httpauth::middleware::HttpAuthentication;
use futures::future;
use mongodb::{Collection, Database};
use bson::{doc};
use std::pin::Pin;

#[derive(serde::Deserialize, serde::Serialize)]
struct JwtToken {
  user_id: i8
}

fn get_header_map<'a>(req: &'a &HttpRequest) -> &'a http::header::HeaderMap {
  req.headers()
}

fn get_auth_header(headers: &http::header::HeaderMap) -> &str {
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

  fn from_request(req: &HttpRequest, _payload: &mut dev::Payload) -> Self::Future {
    let auth_header = get_auth_header(get_header_map(&req));

    decode_token(auth_header)
  }
}

#[derive(serde::Deserialize)]
struct LoginBodyUser {
  email: String,
  password: String
}

#[derive(serde::Deserialize)]
struct LoginBody {
  user: LoginBodyUser
}

struct UserDocument {}

trait UserModel {
  fn valid_password() -> bool;
}

impl UserModel for UserDocument {
  fn valid_password() -> bool {
    true
  }
}

fn authenticate(
  LoginBodyUser { email, password: _password }: &LoginBodyUser,
  db: web::Data<Database>
) -> Result<bson::Document, &str> {
  let document = db
    .collection("users")
    .find_one(bson::doc! { email: email }, None);

  match document {
    Ok(user_option) => match user_option {
      Some(user) => Ok(user),
      None => Err("Invalid email or password")
    },
    Err(error) => {
      println!("{}", error);
      Err("Error connecting to database")
    }
  }
}

pub fn router(cfg: &mut web::ServiceConfig) {
  cfg
    .service(
      web::resource("/user/login").route(
        web::post().to(|body: web::Json<LoginBody>, db: web::Data<Database>| {
          match authenticate(&body.user, db) {
            Ok(_) => HttpResponse::Ok(),
            Err(err) => {
              println!("{}", err);
              HttpResponse::InternalServerError()
            }
          }
        })
      )
    )
    .service(
      web::resource("/user")
        .wrap(HttpAuthentication::bearer(|req, _credentials| async { Ok(req) }))
        .route(web::get().to(|token: JwtToken| HttpResponse::Ok().json(token)))
    )
    .service(
      web::resource("/users").route(
        web::post()
          .to(|_body: web::Json<LoginBody>, state: web::Data<crate::AppState>| {
            let users: Collection = state.db.collection("users");

            match users.insert_one(doc! {}, None) {
              Ok(_) => HttpResponse::Created(),
              Err(err) => {
                println!("{}", err);
                HttpResponse::InternalServerError()
              }
            }
          })
      )
    );
}
