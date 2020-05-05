use actix_web::{Error, HttpRequest, HttpResponse, FromRequest, dev, error, web};
use actix_web::http::header::HeaderMap;
use actix_web_httpauth::middleware::HttpAuthentication;
use futures::future;
use jsonwebtoken::{DecodingKey, EncodingKey, Header, Validation, decode, encode};
use mongodb::{Collection, Database, options::{FindOneAndUpdateOptions, ReturnDocument}};
use bson::{doc};
use std::pin::Pin;
use validator::{Validate};
use serde::{Deserialize, Serialize};

#[derive(Deserialize, Serialize)]
struct UserClaims {
  exp: i64,
  id: String,
  username: String
}

fn get_header_map(req: &HttpRequest) -> &HeaderMap {
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
      Err(Error::from(error::ErrorUnauthorized("Invalid token")))
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
  id: String,
  image: Option<String>,
  password: String,
  username: String
}

impl From<bson::ordered::OrderedDocument> for User {
  fn from(document: bson::ordered::OrderedDocument) -> Self {
    User {
      bio: match document.get_str("bio") {
        Ok(bio) => Some(bio.to_string()),
        Err(_) => None
      },
      email: match document.get_str("email") {
        Ok(email) => email.to_string(),
        Err(_) => "".to_string()
      },
      id: match document.get_object_id("_id") {
        Ok(id) => id.to_hex(),
        Err(_) => "".to_string()
      },
      image: match document.get_str("image") {
        Ok(image) => Some(image.to_string()),
        Err(_) => None
      },
      password: match document.get_str("password") {
        Ok(password) => password.to_string(),
        Err(_) => "".to_string()
      },
      username: match document.get_str("username") {
        Ok(username) => username.to_string(),
        Err(_) => "".to_string()
      },
    }
  }
}

fn find_by_id(db: &Database, id: &str) -> Option<User> {
  let result = db
    .collection("users")
    .find_one(
      doc!{ "_id": bson::oid::ObjectId::with_string(&id).unwrap() },
      None
    );

  match result {
    Ok(user_option) => {
      match user_option {
        Some(user) => Some(User::from(user)),
        None => None
      }
    },
    Err(_) => None
  }
}

fn authenticate<'login>(
  LoginBodyUser { email, password }: &'login LoginBodyUser,
  db: &Database
) -> Result<User, &'login str> {
  match db.collection("users").find_one(doc!{ "email": email }, None) {
    Ok(user_option) => match user_option {
      Some(user) => {
        let result = pbkdf2::pbkdf2_check(
          password,
          &user.get_str("password").unwrap()
        );

        match result {
          Ok(_) => Ok(User::from(user)),
          Err(_) => Err("Invalid password")
        }
      },
      None => Err("User not found")
    },
    Err(_) => Err("User not found")
  }
}

#[derive(Serialize)]
struct AuthToken {
  bio: Option<String>,
  email: String,
  image: Option<String>,
  token: String,
  username: String
}

#[derive(Serialize)]
struct LoginResponse {
  user: AuthToken
}

fn to_auth_json(user: &User) -> AuthToken {
  let expires_on = chrono::Local::now() + chrono::Duration::days(60);

  AuthToken {
    bio: match user.bio.as_ref() {
      Some(bio) => Some(bio.to_string()),
      None => None
    },
    email: user.email.to_string(),
    image: match user.image.as_ref() {
      Some(image) => Some(image.to_string()),
      None => None
    },
    token: encode(
      &Header::default(),
      &UserClaims {
        exp: expires_on.timestamp(),
        id: String::from(&user.id),
        username: String::from(&user.username)
      },
      &EncodingKey::from_secret("secret".as_ref())
    ).unwrap(),
    username: String::from(&user.username)
  }
}

fn login(
  body: web::Json<LoginBody>,
  state: web::Data<crate::AppState>
) -> HttpResponse {
  match authenticate(&body.user, &state.db) {
    Ok(user) => HttpResponse::Ok().json(LoginResponse { user: to_auth_json(&user) }),
    Err(err) => {
      println!("{}", err);
      HttpResponse::InternalServerError().finish()
    }
  }
}

fn get_user(
  token: UserClaims,
  state: web::Data<crate::AppState>
) -> HttpResponse {
  match find_by_id(&state.db, &token.id) {
    Some(user) => HttpResponse::Ok().json(to_auth_json(&user)),
    None => HttpResponse::NotFound().finish()
  }
}

#[derive(Deserialize)]
struct UpdateUserEntity {
  bio: Option<String>,
  email: Option<String>,
  image: Option<String>,
  password: Option<String>,
  username: Option<String>
}

#[derive(Deserialize)]
struct UpdateUser {
  user: UpdateUserEntity
}

fn generate_password(password: &str) -> Result<String, std::io::Error> {
  pbkdf2::pbkdf2_simple(password, 16)
}

fn update_user(
  body: web::Json<UpdateUser>,
  token: UserClaims,
  state: web::Data<crate::AppState>
) -> HttpResponse {
  let user = &body.user;

  match find_by_id(&state.db, &token.id) {
    Some(_) => {
      let mut update_doc = doc!{};

      match &user.username {
        Some(username) => {
          update_doc.insert("username", username);
        },
        _ => ()
      };

      match &user.email {
        Some(email) => {
          update_doc.insert("email", email);
        },
        _ => ()
      };

      match &user.bio {
        Some(bio) => {
          update_doc.insert("bio", bio);
        },
        _ => ()
      };

      match &user.image {
        Some(image) => {
          update_doc.insert("image", image);
        },
        _ => ()
      };

      match &user.password {
        Some(password) => {
          update_doc.insert("password", generate_password(password).unwrap());
        },
        _ => ()
      };

      if update_doc.len() == 0 {
        return HttpResponse::UnprocessableEntity().finish();
      }

      let result = state.db
        .collection("users")
        .find_one_and_update(
          doc!{ "_id": bson::oid::ObjectId::with_string(&token.id).unwrap() },
          doc!{ "$set": update_doc },
          FindOneAndUpdateOptions {
            array_filters: None,
            bypass_document_validation: None,
            collation: None,
            max_time: None,
            projection: None,
            return_document: Some(ReturnDocument::After),
            sort: None,
            upsert: None,
            write_concern: None
          }
        );

      match result {
        Ok(result_user) => HttpResponse::Ok().json(result_user),
        Err(err) => {
          println!("{}", err);
          HttpResponse::InternalServerError().finish()
        }
      }
    },
    None => HttpResponse::Unauthorized().finish()
  }
}

pub fn router(cfg: &mut web::ServiceConfig) {
  cfg
    .service(web::resource("/user/login").route(web::post().to(login)))
    .service(
      web::resource("/user")
        .wrap(HttpAuthentication::bearer(|req, _credentials| async { Ok(req) }))
        .route(web::get().to(get_user))
        .route(web::put().to(update_user))
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
                    "password": &generate_password(&body.user.password).unwrap(),
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
