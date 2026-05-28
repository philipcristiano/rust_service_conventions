use axum::{
    response::{IntoResponse, Response},
    routing::get,
    Router,
};
use clap::Parser;
use maud::{html, DOCTYPE};
use serde::{Deserialize, Serialize};
use std::fs;
use std::net::SocketAddr;

use tower_cookies::CookieManagerLayer;
use service_conventions::oidc::GroupClaims; // needs to be pub

#[derive(Parser, Debug)]
pub struct Args {
    #[arg(short, long, default_value = "127.0.0.1:3000")]
    bind_addr: String,
    #[arg(short, long, default_value = "examples/oidc_with_custom_claims/oidc.toml")]
    config_file: String,
    #[arg(short, long, value_enum, default_value = "INFO")]
    log_level: tracing::Level,
    #[arg(long, action)]
    log_json: bool,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct CustomClaims {
    datahub_postgres_role: Vec<String>,
}
use openidconnect::AdditionalClaims;
impl AdditionalClaims for CustomClaims {}


#[derive(Clone, Debug, Deserialize)]
struct AppConfig {
    auth: service_conventions::oidc::OIDCConfig,
}
#[derive(Clone, Debug)]
struct AppState {
    auth: service_conventions::oidc::AuthConfig,
}

impl From<AppConfig> for AppState {
    fn from(item: AppConfig) -> Self {
        let auth_config = service_conventions::oidc::AuthConfig {
            oidc_config: item.auth,
            post_auth_path: "/user".to_string(),
            scopes: vec!["profile".to_string(), "email".to_string()],
        };
        AppState { auth: auth_config }
    }
}
use tracing::Level;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let app = make_app(&args);
    let addr: SocketAddr = args.bind_addr.parse().expect("Expected bind addr");
    tracing::info!("listening on {}", addr);
    let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();
    Ok(axum::serve(listener, app).await.unwrap())
}

fn make_app(args: &Args) -> Router {
    // initialize tracing

    service_conventions::tracing::setup(args.log_level);

    let config_file_error_msg = format!("Could not read config file {}", args.config_file);
    let config_file_contents =
        fs::read_to_string(args.config_file.clone()).expect(&config_file_error_msg);

    let app_config: AppConfig =
        toml::from_str(&config_file_contents).expect("Problems parsing config file");
    let app_state: AppState = app_config.into();

    let oidc_router = service_conventions::oidc::router_with_claims::<CustomClaims>(app_state.auth.clone());
    Router::new()
        // `GET /` goes to `root`
        .route("/", get(root))
        .route("/user", get(user_handler))
        .nest("/oidc", oidc_router)
        .with_state(app_state.auth.clone())
        .layer(CookieManagerLayer::new())
        .layer(service_conventions::tracing_http::trace_layer(Level::INFO))
        .route("/_health", get(health))
}
// basic handler that responds with a static string
async fn root() -> Response {
    html! {
       (DOCTYPE)
            p { "Welcome!"}
            a href="/oidc/login" { "Login" }
    }
    .into_response()
}

async fn health() -> Response {
    "OK".into_response()
}

async fn user_handler(user: Option<service_conventions::oidc::OIDCUser<CustomClaims>>) -> Response {
    tracing::info!(user=?user, "User received");
    if let Some(user) = user {
        html! {
         (DOCTYPE)
              p { "Welcome! " ( user.id)}
              @if let Some(name) = user.name {
                  p{ ( name ) }
              }
              @if let Some(email) = user.email {
                  p{ ( email ) }
              }
              h3 { "custom_claim" }
              ul {
                @for role in &user.additional_claims.datahub_postgres_role {
                    li { (role) }
                }
              }

              a href="/oidc/login" { "Login" }
        }
        .into_response()
    } else {
        html! {
         (DOCTYPE)
            p { "Welcome! You need to login" }
            a href="/oidc/login" { "Login" }
        }
        .into_response()
    }
}

mod tests {
    use super::*;
    use axum::{
        body::Body,
        extract::connect_info::MockConnectInfo,
        http::{self, Request, StatusCode},
    };
    use tower::{Service, ServiceExt};

    fn default_args() -> Args {
        Args {
            bind_addr: "0".to_string(),
            config_file: "examples/hello_idc/oidc.toml".to_string(),
            log_level: tracing::Level::DEBUG,
            log_json: false,
        }
    }

    #[tokio::test]
    async fn test_listen_test() {
        // using common code.
        let args = default_args();
        let app = make_app(&args);
        let resp = app
            .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        //assert!(query.is_ok())
    }
}
