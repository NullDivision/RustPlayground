use actix_web::{Error, HttpRequest, HttpResponse, FromRequest, dev, web};
use actix_web::http::header::HeaderMap;
use actix_web_httpauth::middleware::HttpAuthentication;
use futures::future;
use jsonwebtoken::{DecodingKey, EncodingKey, Header, Validation, decode, encode};
use mongodb::{Collection, Database};
use bson::{doc};
use std::pin::Pin;
use validator::{Validate};
use serde::{Deserialize, Serialize};

#[derive(Deserialize, Serialize)]
struct UserClaims {
  exp: i64,
  email: String
}

fn get_header_map<'a>(req: &'a &HttpRequest) -> &'a HeaderMap {
  req.headers()
}

fn get_auth_header(headers: &HeaderMap) -> &str {
  match headers.get("Authorization") {
    Some(v) => &v.to_str().unwrap()[7..],
    None => ""
  }
}

fn decode_token(auth_header: &str) -> Pin<Box<dyn future::Future<Output = Result<UserClaims, Error>>>> {
  let decode_value = decode::<UserClaims>(
    auth_header,
    &DecodingKey::from_secret(&"secret".as_ref()),
    &Validation::default()
  );

  match decode_value {
    Ok(v) => Box::pin(async move {
      Ok(v.claims)
    }),
    Err(v) => Box::pin(async move {
      println!("{}", v);
      Ok(UserClaims { exp: 0, email: "".to_string() })
    })
  }
}

impl FromRequest for UserClaims {
  type Error = Error;
  type Future = Pin<Box<dyn future::Future<Output = Result<UserClaims, Error>>>>;
  type Config = ();

  fn from_request(req: &HttpRequest, _payload: &mut dev::Payload) -> Self::Future {
    let auth_header = get_auth_header(get_header_map(&req));

    decode_token(auth_header)
  }
}

#[derive(Deserialize, Validate)]
struct LoginBodyUser {
  #[validate(email)]
  email: String,
  password: String
}

#[derive(Deserialize, Validate)]
struct LoginBody {
  #[validate]
  user: LoginBodyUser
}

#[derive(Deserialize, Validate)]
struct CreateBodyUser {
  email: String,
  password: String,
  username: String,
}

#[derive(Deserialize, Validate)]
struct CreateBody {
  #[validate]
  user: CreateBodyUser
}

#[derive(Deserialize)]
struct User {
  bio: Option<String>,
  email: String,
  image: Option<String>,
  password: String,
  username: String
}

fn find_by_email(db: &Database, email: &str) -> Option<User> {
  match db.collection("users").find_one(doc! { "email": &email }, None) {
    Ok(user_option) => {
      match user_option {
        Some(user) => bson::from_bson(bson::Bson::Document(user)).unwrap(),
        None => None
      }
    },
    Err(_) => None
  }
}

fn authenticate(
  LoginBodyUser { email, password }: &LoginBodyUser,
  db: &Database
) -> Result<User, &'static str> {
  match find_by_email(db, email) {
    Some(user) => {
      let result = pbkdf2::pbkdf2_check(
        password,
        &user.password
      );

      match result {
        Ok(_) => Ok(user),
        Err(_) => Err("Invalid password")
      }
    },
    None => Err("User not found")
  }
}

#[derive(Serialize)]
struct LoginResponseUser {
  bio: Option<String>,
  email: String,
  image: Option<String>,
  token: String,
  username: String
}

#[derive(Serialize)]
struct LoginResponse {
  user: LoginResponseUser
}

fn to_auth_json(user: User) -> LoginResponse {
  let expires_on = chrono::Local::now() + chrono::Duration::days(60);

  LoginResponse {
    user: LoginResponseUser {
      bio: user.bio,
      email: user.email.to_string(),
      image: user.image,
      token: encode(
        &Header::default(),
        &UserClaims {
          email: user.email,
          exp: expires_on.timestamp()
        },
        &EncodingKey::from_secret("secret".as_ref())
      ).unwrap(),
      username: user.username
    }
  }
}

fn login(
  body: web::Json<LoginBody>,
  state: web::Data<crate::AppState>
) -> HttpResponse {
  match authenticate(&body.user, &state.db) {
    Ok(user) => HttpResponse::Ok().json(to_auth_json(user)),
    Err(err) => {
      println!("{}", err);
      HttpResponse::InternalServerError().finish()
    }
  }
}

pub fn router(cfg: &mut web::ServiceConfig) {
  cfg
    .service(web::resource("/user/login").route(web::post().to(login)))
    .service(
      web::resource("/user")
        .wrap(HttpAuthentication::bearer(|req, _credentials| async { Ok(req) }))
        .route(
          web::get()
            .to(|token: UserClaims, state: web::Data<crate::AppState>| {
              match find_by_email(&state.db, &token.email) {
                Some(user) => HttpResponse::Ok().json(to_auth_json(user)),
                None => HttpResponse::NotFound().finish()
              }
            })
        )
    )
    .service(
      web::resource("/users").route(
        web::post()
          .to(|body: web::Json<CreateBody>, state: web::Data<crate::AppState>| {
            match body.validate() {
              Ok(_) => {
                let users: Collection = state.db.collection("users");
                let result = users.insert_one(
                  doc! {
                    "email": &body.user.email,
                    "password": &pbkdf2::pbkdf2_simple(&body.user.password, 16)
                      .unwrap(),
                    "username": &body.user.username
                  },
                  None
                );

                match result {
                  Ok(_) => HttpResponse::Created().finish(),
                  Err(err) => {
                    println!("{}", err);
                    HttpResponse::InternalServerError().finish()

                  }
                }
              }
              Err(err) => HttpResponse::BadRequest().json(err)
            }
          })
      )
    );
}
