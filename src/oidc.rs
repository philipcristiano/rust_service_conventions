use anyhow::anyhow;
use openidconnect::core::{
    CoreAuthenticationFlow, CoreClient, CoreGenderClaim, CoreProviderMetadata,
};
use openidconnect::{
    AccessTokenHash, AdditionalClaims, AuthorizationCode, ClientId, ClientSecret, CsrfToken,
    EmptyAdditionalClaims, IdTokenClaims, IssuerUrl, Nonce, PkceCodeChallenge, PkceCodeVerifier,
    RedirectUrl, Scope, UserInfoClaims,
};
use serde::{Deserialize, Serialize};
use std::str::FromStr;

use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::{IntoResponse, Redirect, Response},
    routing::get,
    Router,
};
use chrono::{DateTime, Utc};
use openidconnect::reqwest::async_http_client;
use tower_cookies::{Cookie, Cookies, Key};
use url::Url;

use maud::{html, DOCTYPE};
use redacted::FullyRedacted;
use std::error::Error;

#[derive(Clone, Debug, Deserialize)]
pub struct OIDCConfig {
    pub issuer_url: Url,
    pub redirect_url: RedirectUrl,
    pub client_id: String,
    pub client_secret: ClientSecret,
    pub key: FullyRedacted<String>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct AuthConfig {
    pub oidc_config: OIDCConfig,
    pub post_auth_path: String,
    pub scopes: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct OIDCUser {
    pub id: String,
    pub name: Option<String>,
    pub expiration: DateTime<Utc>,
    pub email: Option<email_address::EmailAddress>,
    pub groups: Vec<String>,
    pub scopes: Vec<String>,
}
impl OIDCUser {
    fn from_claims(
        uic: &UserInfoClaims<GroupClaims, CoreGenderClaim>,
        expiration: DateTime<Utc>,
    ) -> Self {
        OIDCUser {
            id: uic.standard_claims().subject().as_str().into(),
            name: uic_name_to_name(uic.standard_claims().name()),
            email: uic_email_to_email(uic.standard_claims().email()),
            groups: uic.additional_claims().groups.clone(),
            scopes: uic.additional_claims().scopes.clone(),
            expiration,
        }
    }
}
fn uic_email_to_email(
    uice: Option<&openidconnect::EndUserEmail>,
) -> Option<email_address::EmailAddress> {
    email_address::EmailAddress::from_str(uice?).ok()
}
fn uic_name_to_name(
    uicn: Option<&openidconnect::LocalizedClaim<openidconnect::EndUserName>>,
) -> Option<String> {
    for (language_tag, i) in uicn?.iter() {
        return Some(i.as_str().to_string());
    }
    None
}

use async_trait::async_trait;
use axum_core::extract::FromRequestParts;
use http::request::Parts;
const USER_COOKIE_NAME: &str = "oidc_user";
#[async_trait]
impl<S> FromRequestParts<S> for OIDCUser
where
    S: Send + Sync,
{
    type Rejection = (http::StatusCode, &'static str);

    async fn from_request_parts(req: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let cookies = Cookies::from_request_parts(req, state).await?;
        let key = KEY.get().unwrap();
        let private_cookies = cookies.private(key);

        let cookie = match private_cookies.get(USER_COOKIE_NAME) {
            Some(c) => c,
            _ => return Err((StatusCode::BAD_REQUEST, "User Cookie problem a")),
        };
        let oidc_user = serde_json::from_str(&cookie.value());

        match oidc_user {
            Err(e) => {
                tracing::error!("User Cookie problem {:?}", e);
                Err((StatusCode::BAD_REQUEST, "User Cookie problem"))
            }
            Ok(ou) => Ok(ou),
        }
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct AuthContent {
    pub redirect_url: Url,
    pub verify: AuthVerify,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct AuthVerify {
    pkce_verifier: PkceCodeVerifier,
    nonce: Nonce,
    pub csrf_token: CsrfToken,
}

#[derive(Debug, Deserialize, Serialize)]
struct GroupClaims {
    #[serde(default)]
    scopes: Vec<String>,
    #[serde(default)]
    groups: Vec<String>,
}

impl AdditionalClaims for GroupClaims {}

// Use OpenID Connect Discovery to fetch the provider metadata.
use openidconnect::{OAuth2TokenResponse, TokenResponse};

#[tracing::instrument]
pub async fn construct_client(auth_config: AuthConfig) -> Result<CoreClient, Box<dyn Error>> {
    let provider_metadata = CoreProviderMetadata::discover_async(
        //&IssuerUrl::new("https://accounts.example.com".to_string())?,
        IssuerUrl::from_url(auth_config.oidc_config.issuer_url),
        async_http_client,
    )
    .await?;

    let client = CoreClient::from_provider_metadata(
        provider_metadata,
        //ClientId::new("client_id".to_string()),
        //Some(ClientSecret::new("client_secret".to_string())),
        ClientId::new(auth_config.oidc_config.client_id),
        Some(auth_config.oidc_config.client_secret),
    )
    // Set the URL the user will be redirected to after the authorization process.
    //.set_redirect_uri(RedirectUrl::new("http://redirect".to_string())?);
    .set_redirect_uri(auth_config.oidc_config.redirect_url);
    return Ok(client);
}

#[tracing::instrument]
pub async fn get_auth_url(config: &AuthConfig, client: CoreClient) -> AuthContent {
    // Create an OpenID Connect client by specifying the client ID, client secret, authorization URL
    // and token URL.

    // Generate a PKCE challenge.
    let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();

    // Generate the full authorization URL.
    let mut url_builder = client.authorize_url(
        CoreAuthenticationFlow::AuthorizationCode,
        CsrfToken::new_random,
        Nonce::new_random,
    );

    for scope in &config.scopes {
        url_builder = url_builder.add_scope(Scope::new(scope.clone()));
    }

    let (auth_url, csrf_token, nonce) = url_builder
        .set_pkce_challenge(pkce_challenge)
        // Set the PKCE code challenge and generate URL
        .url();

    // This is the URL you should redirect the user to, in order to trigger the authorization
    // process.
    let ac = AuthContent {
        redirect_url: auth_url,
        verify: AuthVerify {
            csrf_token,
            pkce_verifier,
            nonce,
        },
    };
    return ac;
}

#[tracing::instrument]
pub async fn next(
    client: CoreClient,
    auth_verify: AuthVerify,
    auth_code: String,
) -> anyhow::Result<OIDCUser> {
    // Once the user has been redirected to the redirect URL, you'll have access to the
    // authorization code. For security reasons, your code should verify that the `state`
    // parameter returned by the server matches `csrf_state`.

    // Now you can exchange it for an access token and ID token.
    let token_response = client
        .exchange_code(AuthorizationCode::new(auth_code))
        // Set the PKCE code verifier.
        .set_pkce_verifier(auth_verify.pkce_verifier)
        .request_async(async_http_client)
        .await?;

    // Extract the ID token claims after verifying its authenticity and nonce.
    let id_token = token_response
        .id_token()
        .ok_or_else(|| anyhow!("Server did not return an ID token"))?;
    let claims = id_token.claims(&client.id_token_verifier(), &auth_verify.nonce)?;
    claims.expiration();

    // Verify the access token hash to ensure that the access token hasn't been substituted for
    // another user's.
    if let Some(expected_access_token_hash) = claims.access_token_hash() {
        let actual_access_token_hash =
            AccessTokenHash::from_token(token_response.access_token(), &id_token.signing_alg()?)?;
        if actual_access_token_hash != *expected_access_token_hash {
            return Err(anyhow!("Invalid access token"));
        }
    }

    // The authenticated user's identity is now available. See the IdTokenClaims struct for a
    // complete listing of the available claims.
    // The user_info request uses the AccessToken returned in the token response. To parse custom
    // claims, use UserInfoClaims directly (with the desired type parameters) rather than using the
    // CoreUserInfoClaims type alias.
    let userinfo_claims: UserInfoClaims<GroupClaims, CoreGenderClaim> = client
        .user_info(token_response.access_token().to_owned(), None)
        .map_err(|err| anyhow!("No user info endpoint: {:?}", err))?
        .request_async(async_http_client)
        .await
        .map_err(|err| anyhow!("Failed requesting user info: {:?}", err))?;
    tracing::debug!("Userinfo claims: {:?}", userinfo_claims);
    // If available, we can use the UserInfo endpoint to request additional information.
    return Ok(OIDCUser::from_claims(&userinfo_claims, claims.expiration()));
}

pub fn router(auth_config: AuthConfig) -> axum::Router<AuthConfig> {
    let keyval = Key::try_from(auth_config.oidc_config.key.into_inner().as_bytes())
        .expect("Key must be >=64 bytes");
    KEY.set(keyval).ok();
    let r = Router::new()
        .route("/login", get(oidc_login))
        .route("/login_auth", get(login_auth));
    r
}
const COOKIE_NAME: &str = "auth_flow";
#[tracing::instrument]
async fn oidc_login(State(config): State<AuthConfig>, cookies: Cookies) -> impl IntoResponse {
    let auth_client = construct_client(config.clone()).await.unwrap();
    let auth_content = get_auth_url(&config, auth_client).await;
    let key = KEY.get().unwrap();
    let private_cookies = cookies.private(key);
    let cookie_val = serde_json::to_string(&auth_content.verify).unwrap();
    private_cookies.add(Cookie::new(COOKIE_NAME, cookie_val));

    Redirect::temporary(&auth_content.redirect_url.to_string())
}

#[derive(Debug, Deserialize)]
struct OIDCAuthCode {
    code: String,
    state: String,
}

#[derive(Debug)]
struct AuthError(anyhow::Error);

// Tell axum how to convert `AppError` into a response.
impl IntoResponse for AuthError {
    fn into_response(self) -> Response {
        tracing::info!("Auth error {:?}", self);
        let resp = html! {

        (DOCTYPE)
            p { "You are not authorized"}
            a href="/oidc/login" { "Restart" }
        };
        (StatusCode::UNAUTHORIZED, resp).into_response()
    }
}

// This enables using `?` on functions that return `Result<_, anyhow::Error>` to turn them into
// `Result<_, AppError>`. That way you don't need to do that manually.
impl<E> From<E> for AuthError
where
    E: Into<anyhow::Error>,
{
    fn from(err: E) -> Self {
        Self(err.into())
    }
}

use once_cell::sync::OnceCell;
static KEY: OnceCell<Key> = OnceCell::new();

#[tracing::instrument]
async fn login_auth(
    State(config): State<AuthConfig>,
    cookies: Cookies,
    Query(oidc_auth_code): Query<OIDCAuthCode>,
) -> Result<Response, AuthError> {
    let auth_client = construct_client(config.clone()).await.unwrap();
    let key = KEY.get().unwrap();
    let private_cookies = cookies.private(key);
    let cookie = match private_cookies.get(COOKIE_NAME) {
        Some(c) => c,
        _ => return Ok(StatusCode::UNAUTHORIZED.into_response()),
    };

    let cookie_str = cookie.value();
    let auth_verify: AuthVerify = serde_json::from_str(&cookie_str)?;

    if auth_verify.csrf_token.secret() != &oidc_auth_code.state {
        tracing::error!("CSRF State doesn't match");
        return Ok(StatusCode::UNAUTHORIZED.into_response());
    }

    let oidc_user = next(auth_client, auth_verify, oidc_auth_code.code).await?;
    let cookie_val_user = serde_json::to_string(&oidc_user).unwrap();
    let mut user_cookie = Cookie::new(USER_COOKIE_NAME, cookie_val_user);
    let max_age = oidc_user.expiration - chrono::Utc::now();
    let max_age_duration = tower_cookies::cookie::time::Duration::new(max_age.num_seconds(), 0);
    user_cookie.set_path("/");
    user_cookie.set_max_age(Some(max_age_duration));
    private_cookies.add(user_cookie);

    Ok(Redirect::to(&config.post_auth_path).into_response())
}
