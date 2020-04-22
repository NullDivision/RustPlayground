use actix_web::{web};

mod api;

pub fn router(cfg: &mut web::ServiceConfig) {
  cfg.service(web::scope("/api").configure(api::router));
}
