use actix_web::{web};

pub fn router(cfg: &mut web::ServiceConfig) {
  cfg
    .service(web::scope("/articles"))
    .service(web::scope("/profiles"))
    .service(web::scope("/tags"))
    .service(web::scope("/"));
}
