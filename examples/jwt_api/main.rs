use axum::{
    extract::State,
    response::{IntoResponse, Response},
    routing::get,
    Router,
};
use clap::Parser;
use maud::{html, DOCTYPE};
use serde::{Deserialize, Serialize};
use std::fs;
use std::net::SocketAddr;

use http::status::StatusCode;
use service_conventions::jwt::{ClaimsGuard, JWTClaims};

#[derive(Serialize, Deserialize, Debug)]
pub struct APIClaims {
    pub sub: String,
    pub role: String, // must equal "admin" — validated below
}

// Then per-claims-type:
impl ClaimsGuard for APIClaims {
    fn authorize(&self) -> Result<(), String> {
        if self.role == "admin" {
            Ok(())
        } else {
            Err("Admin only".to_string())
        }
    }
}

#[derive(Parser, Debug)]
pub struct Args {
    #[arg(short, long, default_value = "127.0.0.1:3000")]
    bind_addr: String,
    #[arg(short, long, default_value = "examples/jwt_api/jwt.toml")]
    config_file: String,
    #[arg(short, long, value_enum, default_value = "INFO")]
    log_level: tracing::Level,
    #[arg(long, action)]
    log_json: bool,
}

#[derive(Clone, Debug, Deserialize)]
struct AppConfig {
    jwt: service_conventions::jwt::JWTConfig,
}

#[derive(Clone, Debug)]
struct AppState {
    addr: SocketAddr,
}

use tracing::Level;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let addr: SocketAddr = args.bind_addr.parse().expect("Expected bind addr");
    let app = make_app(&addr, &args);
    tracing::info!("listening on {}", addr);
    let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();
    Ok(axum::serve(listener, app).await.unwrap())
}

fn make_app(addr: &SocketAddr, args: &Args) -> Router {
    // initialize tracing

    service_conventions::tracing::setup(args.log_level);

    let config_file_error_msg = format!("Could not read config file {}", args.config_file);
    let config_file_contents =
        fs::read_to_string(args.config_file.clone()).expect(&config_file_error_msg);

    let app_config: AppConfig =
        toml::from_str(&config_file_contents).expect("Problems parsing config file");
    let app_state = AppState { addr: addr.clone() };
    service_conventions::jwt::init(app_config.jwt);

    Router::new()
        .route("/", get(root))
        .route("/api", get(api_handler))
        .with_state(app_state.clone())
        .layer(service_conventions::tracing_http::trace_layer(Level::INFO))
        .route("/_health", get(health))
}
// basic handler that responds with a static string
async fn root(State(state): State<AppState>) -> Response {
    let new_credentials = APIClaims {
        sub: "jwt_api_example".to_string(),
        role: "example".to_string(), // must equal "admin" — validated below
    };
    let token = service_conventions::jwt::sign(new_credentials).expect("blah");
    html! {
       (DOCTYPE)
            p { "Welcome!"}
            p {"`curl -H \"Authorization: Bearer " (token) "\" http://"( state.addr) "/api"}
            p {"`curl -H \"Authorization: Bearer INVALID_TOKEN\" http://"( state.addr) "/api"}
            a href="/oidc/login" { "Login" }
    }
    .into_response()
}

async fn health() -> Response {
    "OK".into_response()
}

async fn api_handler(api_claims: JWTClaims<APIClaims>) -> Response {
    println!("Claims {api_claims:?}");
    (StatusCode::OK, "OK").into_response()
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
            bind_addr: "0.0.0.0:1234".to_string(),
            config_file: "examples/jwt_api/jwt.toml".to_string(),
            log_level: tracing::Level::DEBUG,
            log_json: false,
        }
    }

    #[tokio::test]
    async fn test_listen_test() {
        // using common code.
        let args = default_args();
        let addr: SocketAddr = args.bind_addr.parse().expect("Expected bind addr");
        let app: Router = make_app(&addr, &args);
        let resp = app
            .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        //assert!(query.is_ok())
    }
}
