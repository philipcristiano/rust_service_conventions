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

use openidconnect::reqwest::async_http_client;
use url::Url;
use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::{IntoResponse, Redirect, Response},
    routing::get,
    Router,
};
use tower_cookies::{Cookie, CookieManagerLayer, Cookies, Key};

use std::error::Error;
use maud::{html, DOCTYPE};

#[derive(Clone, Debug, Deserialize)]
pub struct AuthConfig {
    issuer_url: Url,
    redirect_url: RedirectUrl,
    client_id: String,
    client_secret: ClientSecret,
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
    scopes: Vec<String>,
    groups: Vec<String>,
}
impl AdditionalClaims for GroupClaims {}

// Use OpenID Connect Discovery to fetch the provider metadata.
use openidconnect::{OAuth2TokenResponse, TokenResponse};

#[tracing::instrument]
pub async fn construct_client(auth_config: AuthConfig) -> Result<CoreClient, Box<dyn Error>> {
    let provider_metadata = CoreProviderMetadata::discover_async(
        //&IssuerUrl::new("https://accounts.example.com".to_string())?,
        IssuerUrl::from_url(auth_config.issuer_url),
        async_http_client,
    )
    .await?;

    let client = CoreClient::from_provider_metadata(
        provider_metadata,
        //ClientId::new("client_id".to_string()),
        //Some(ClientSecret::new("client_secret".to_string())),
        ClientId::new(auth_config.client_id),
        Some(auth_config.client_secret),
    )
    // Set the URL the user will be redirected to after the authorization process.
    //.set_redirect_uri(RedirectUrl::new("http://redirect".to_string())?);
    .set_redirect_uri(auth_config.redirect_url);
    return Ok(client);
}

#[tracing::instrument]
pub async fn get_auth_url(client: CoreClient) -> AuthContent {
    // Create an OpenID Connect client by specifying the client ID, client secret, authorization URL
    // and token URL.

    // Generate a PKCE challenge.
    let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();

    // Generate the full authorization URL.
    let (auth_url, csrf_token, nonce) = client
        .authorize_url(
            CoreAuthenticationFlow::AuthorizationCode,
            CsrfToken::new_random,
            Nonce::new_random,
        )
        // Set the desired scopes.
        .add_scope(Scope::new("profile".to_string()))
        .add_scope(Scope::new("email".to_string()))
        // Set the PKCE code challenge.
        .set_pkce_challenge(pkce_challenge)
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
) -> anyhow::Result<IdTokenClaims<EmptyAdditionalClaims, CoreGenderClaim>> {
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
    println!(
        "User {} with e-mail address {} has authenticated successfully",
        claims.subject().as_str(),
        claims
            .email()
            .map(|email| email.as_str())
            .unwrap_or("<not provided>"),
    );
    // The user_info request uses the AccessToken returned in the token response. To parse custom
    // claims, use UserInfoClaims directly (with the desired type parameters) rather than using the
    // CoreUserInfoClaims type alias.
    let userinfo_claims: UserInfoClaims<GroupClaims, CoreGenderClaim> = client
        .user_info(token_response.access_token().to_owned(), None)
        .map_err(|err| anyhow!("No user info endpoint: {:?}", err))?
        .request_async(async_http_client)
        .await
        .map_err(|err| anyhow!("Failed requesting user info: {:?}", err))?;

    println!("Userinfo: {:?},", userinfo_claims);

    // If available, we can use the UserInfo endpoint to request additional information.

    // The user_info request uses the AccessToken returned in the token response. To parse custom
    // claims, use UserInfoClaims directly (with the desired type parameters) rather than using the
    // CoreUserInfoClaims type alias.

    // See the OAuth2TokenResponse trait for a listing of other available fields such as
    // access_token() and refresh_token().
    return Ok(claims.clone());
}


pub fn router(auth_config: AuthConfig) -> axum::Router<AuthConfig> {
    let my_key: &[u8] = &[0; 64]; // Your real key must be cryptographically random
    KEY.set(Key::from(my_key)).ok();
    let r = Router::new()
        .route("/login",
            get(oidc_login).with_state(auth_config.clone()))
        .route("/login_auth", get(login_auth))
        .with_state(auth_config.clone());
    r

}
const COOKIE_NAME: &str = "auth_flow";
#[tracing::instrument]
async fn oidc_login(State(config): State<AuthConfig>, cookies: Cookies) -> impl IntoResponse {
    let auth_client = construct_client(config.clone()).await.unwrap();
    let auth_content = get_auth_url(auth_client).await;
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

// impl From<serde_json::Error> for AuthError {
//     fn from(_err: serde_json::Error) -> AuthError {
//         AuthError(anyhow::anyhow!("Json serialization error"))
//     }
// }
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

    tracing::error!("CSRF {:?} {:?} {:?}", cookie_str, auth_verify.csrf_token, oidc_auth_code.state);
    if auth_verify.csrf_token.secret() != &oidc_auth_code.state {
        tracing::error!("CSRF State doesn't match");
        return Ok(StatusCode::UNAUTHORIZED.into_response());
    }

    let claims = next(auth_client, auth_verify, oidc_auth_code.code).await?;

    let resp = html! {
        (DOCTYPE)
        p { "User " (claims.subject().as_str()) " has authenticated successfully"}
        p { "Email: " (
                        claims
                        .email()
                        .map(|email| email.as_str())
                        .unwrap_or("<not provided>")) }
        a href="/oidc/login" { "Restart" }
    };

    Ok(resp.into_response())
}
