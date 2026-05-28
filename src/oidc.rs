use anyhow::anyhow;
use openidconnect::core::{
    CoreAuthenticationFlow, CoreClient, CoreGenderClaim, CoreProviderMetadata,

};
use openidconnect::{
    AccessTokenHash, AdditionalClaims, AuthorizationCode, ClientId, ClientSecret, CsrfToken,
    IssuerUrl, Nonce, PkceCodeChallenge, PkceCodeVerifier,
    RedirectUrl, RefreshToken, Scope, UserInfoClaims,
    EndpointSet, EndpointMaybeSet, EndpointNotSet,
};

use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::str::FromStr;

use axum::{
    extract::{FromRef, Query, State},
    http::StatusCode,
    response::{IntoResponse, Redirect, Response},
    routing::get,
    Router,
};
use chrono::{DateTime, Utc};
use tower_cookies::{Cookie, Cookies, Key};
use url::Url;

use maud::{html, DOCTYPE};
use redacted::FullyRedacted;

type CoreClientFromDiscovery = CoreClient<EndpointSet, EndpointNotSet, EndpointNotSet, EndpointNotSet, EndpointMaybeSet, EndpointMaybeSet>;

pub trait OIDCClaims: AdditionalClaims + DeserializeOwned + Serialize + Clone + 'static {}
impl<T: AdditionalClaims + DeserializeOwned + Serialize + Clone + 'static> OIDCClaims for T {}
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

#[derive(Clone, Debug, Serialize)]
pub struct OIDCUser<C: OIDCClaims> {
    pub id: String,
    pub name: Option<String>,
    pub expiration: DateTime<Utc>,
    pub email: Option<email_address::EmailAddress>,
    pub additional_claims: C,
    #[serde(skip_serializing)]
    pub refresh_token: Option<RefreshToken>,
}
impl<C: OIDCClaims> OIDCUser<C> {
    fn from_claims(
        uic: &UserInfoClaims<C, CoreGenderClaim>,  // was AdditionalClaims, should be C
        refresh_token: Option<RefreshToken>,
        expiration: DateTime<Utc>,
    ) -> Self {
        Self {
            id: uic.standard_claims().subject().as_str().into(),
            name: uic_name_to_name(uic.standard_claims().name()),
            email: uic_email_to_email(uic.standard_claims().email()),
            additional_claims: uic.additional_claims().clone(),
            expiration,
            refresh_token,
        }
    }
}

// DeserializeOwned conflicts with the derive for Deserialize, add an implementation for it
// directly
impl<'de, C: OIDCClaims> Deserialize<'de> for OIDCUser<C> {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(field_identifier, rename_all = "snake_case")]
        enum Field { Id, Name, Expiration, Email, AdditionalClaims, RefreshToken }

        struct OIDCUserVisitor<C: OIDCClaims>(std::marker::PhantomData<C>);

        impl<'de, C: OIDCClaims> serde::de::Visitor<'de> for OIDCUserVisitor<C> {
            type Value = OIDCUser<C>;

            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("struct OIDCUser")
            }

            fn visit_map<A: serde::de::MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
                let mut id = None;
                let mut name = None;
                let mut expiration = None;
                let mut email = None;
                let mut additional_claims = None;
                let mut refresh_token = None;

                while let Some(key) = map.next_key()? {
                    match key {
                        Field::Id => { id = Some(map.next_value()?); }
                        Field::Name => { name = Some(map.next_value()?); }
                        Field::Expiration => { expiration = Some(map.next_value()?); }
                        Field::Email => { email = Some(map.next_value()?); }
                        Field::AdditionalClaims => { additional_claims = Some(map.next_value()?); }
                        Field::RefreshToken => { refresh_token = Some(map.next_value()?); }
                    }
                }

                Ok(OIDCUser {
                    id: id.ok_or_else(|| serde::de::Error::missing_field("id"))?,
                    name: name.unwrap_or(None),
                    expiration: expiration.ok_or_else(|| serde::de::Error::missing_field("expiration"))?,
                    email: email.unwrap_or(None),
                    additional_claims: additional_claims.ok_or_else(|| serde::de::Error::missing_field("additional_claims"))?,
                    refresh_token: refresh_token.unwrap_or(None),
                })
            }
        }

        deserializer.deserialize_map(OIDCUserVisitor(std::marker::PhantomData))
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
    for (_language_tag, i) in uicn?.iter() {
        return Some(i.as_str().to_string());
    }
    None
}

use thiserror::Error;
#[derive(Error, Debug)]
pub enum OIDCUserError {
    #[error("Error loading cookies")]
    CookieLoadError,
    #[error("Missing Cookie")]
    MissingCookie,
    #[error("Problem during cookie Deserialize {0}")]
    CookieDeserializeError(serde_json::Error),
    #[error("Problem with constructing OIDC infra {0}")]
    ServerError(#[from] anyhow::Error),
    #[error("Problem refreshing user")]
    RefreshUserError,
}
impl axum::response::IntoResponse for OIDCUserError {
    fn into_response(self) -> Response {
        let r = match self {
            OIDCUserError::CookieLoadError => (StatusCode::BAD_REQUEST, "Error loading cookies"),
            OIDCUserError::MissingCookie => (StatusCode::BAD_REQUEST, "Missing User Cookie"),
            OIDCUserError::CookieDeserializeError(_) => {
                (StatusCode::BAD_REQUEST, "Problem with user cookie")
            }
            OIDCUserError::ServerError(_) => (StatusCode::UNAUTHORIZED, "Problem verifying user"),
            OIDCUserError::RefreshUserError => (StatusCode::BAD_REQUEST, "Unable to refresh user"),
        };
        r.into_response()
    }
}

use axum_core::extract::{FromRequestParts, OptionalFromRequestParts};
use http::request::Parts;

const USER_COOKIE_NAME: &str = "oidc_user";
const REFRESH_COOKIE_NAME: &str = "oidc_user_refresh";

async fn extract_oidc_user_logic<S, C>(req: &mut Parts, state: &S) -> Result<Option<OIDCUser<C>>, OIDCUserError>
where
    S: Send + Sync,
    C: OIDCClaims,
    AuthConfig: FromRef<S>,  // Required to call AuthConfig::from_ref(state)
{
    if let Ok(cookies) = Cookies::from_request_parts(req, state).await {
        let key = KEY.get().unwrap();
        let private_cookies = cookies.private(key);

        match private_cookies.get(USER_COOKIE_NAME) {
            Some(c) => {
                let oidc_user: Result<OIDCUser<C>, _> = serde_json::from_str(&c.value());
                match oidc_user {
                    Err(e) => {
                        tracing::error!("User Cookie problem {:?}", e);
                        return Err(OIDCUserError::CookieDeserializeError(e));
                    }
                    Ok(ou) => return Ok(Some(ou)),
                }
            }
            _ => {
                let extracted_state = AuthConfig::from_ref(state);
                match private_cookies.get(REFRESH_COOKIE_NAME) {
                    Some(refresh_c) => {
                        let client = construct_client(extracted_state).await?;
                        match serde_json::from_str(&refresh_c.value()) {
                            Ok(refresh_cookie_val) => {
                                let me = refresh::<C>(client, refresh_cookie_val).await;
                                if let Ok(oidcuser) = me {
                                    save_user_to_cookies(&oidcuser, &private_cookies);
                                    return Ok(Some(oidcuser));
                                } else {
                                    return Err(OIDCUserError::RefreshUserError);
                                }
                            }
                            Err(e) => return Err(OIDCUserError::CookieDeserializeError(e)),
                        }
                    }
                    _ => return Ok(None), // No user cookie, no refresh token
                }
            }
        }
    } else {
        Err(OIDCUserError::CookieLoadError)
    }
}

impl<S, C> FromRequestParts<S> for OIDCUser<C>
where
    S: Send + Sync,
    C: OIDCClaims,
    AuthConfig: FromRef<S>,
{
    type Rejection = OIDCUserError;

    async fn from_request_parts(req: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        match extract_oidc_user_logic::<S, C>(req, state).await? {
            Some(user) => Ok(user),
            None => Err(OIDCUserError::MissingCookie),
        }
    }
}

impl<S, C> OptionalFromRequestParts<S> for OIDCUser<C>
where
    S: Send + Sync,
    C: OIDCClaims,
    AuthConfig: FromRef<S>,
{
    type Rejection = OIDCUserError;

    async fn from_request_parts(
        req: &mut Parts,
        state: &S,
    ) -> Result<Option<Self>, Self::Rejection> {
        extract_oidc_user_logic::<S, C>(req, state).await
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

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct GroupClaims {
    #[serde(default)]
    pub scopes: Vec<String>,
    #[serde(default)]
    pub groups: Vec<String>,
}

impl AdditionalClaims for GroupClaims {}

// Use OpenID Connect Discovery to fetch the provider metadata.
use openidconnect::{OAuth2TokenResponse, TokenResponse};

#[tracing::instrument(skip_all)]
pub async fn construct_client(auth_config: AuthConfig) -> Result<CoreClientFromDiscovery, anyhow::Error> {
    let async_http_client = openidconnect::reqwest::Client::new();
    let provider_metadata = CoreProviderMetadata::discover_async(
        //&IssuerUrl::new("https://accounts.example.com".to_string())?,
        IssuerUrl::from_url(auth_config.oidc_config.issuer_url),
        &async_http_client,
    )
    .await?;

    let client = CoreClient::from_provider_metadata(
        provider_metadata,
        ClientId::new(auth_config.oidc_config.client_id),
        Some(auth_config.oidc_config.client_secret),
    )
    // Set the URL the user will be redirected to after the authorization process.
    //.set_redirect_uri(RedirectUrl::new("http://redirect".to_string())?);
    .set_redirect_uri(auth_config.oidc_config.redirect_url);
    return Ok(client);
}

#[tracing::instrument(skip_all)]
pub async fn get_auth_url(config: &AuthConfig, client: CoreClientFromDiscovery) -> AuthContent {
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
#[tracing::instrument(skip_all)]
async fn refresh<C: OIDCClaims>(
    client: CoreClientFromDiscovery,
    refresh_token: RefreshToken,
) -> anyhow::Result<OIDCUser<C>> {
    // Once the user has been redirected to the redirect URL, you'll have access to the
    // authorization code. For security reasons, your code should verify that the `state`
    // parameter returned by the server matches `csrf_state`.

    // Now you can exchange it for an access token and ID token.
    let async_http_client = openidconnect::reqwest::Client::new();
    let token_response = client
        .exchange_refresh_token(&refresh_token)?
        // Set the PKCE code verifier.
        .request_async(&async_http_client)
        .await?;
    let maybe_refresh_token = token_response.refresh_token();

    // Extract the ID token claims after verifying its authenticity and nonce.

    if let Some(expires_in) = token_response.expires_in() {
        let expires_at = chrono::Utc::now() + expires_in;

        let userinfo_claims: UserInfoClaims<C, CoreGenderClaim> = client
            .user_info(token_response.access_token().to_owned(), None)
            .map_err(|err| anyhow!("No user info endpoint: {:?}", err))?
            .request_async(&async_http_client)
            .await
            .map_err(|err| anyhow!("Failed requesting user info: {:?}", err))?;
        tracing::debug!("Userinfo claims: {:?}", userinfo_claims);
        // If available, we can use the UserInfo endpoint to request additional information.
        return Ok(OIDCUser::from_claims(
            &userinfo_claims,
            maybe_refresh_token.cloned(),
            expires_at,
        ));
    } else {
        Err(anyhow!("Missing expiry"))
    }
    // The authenticated user's identity is now available. See the IdTokenClaims struct for a
    // complete listing of the available claims.
    // The user_info request uses the AccessToken returned in the token response. To parse custom
    // claims, use UserInfoClaims directly (with the desired type parameters) rather than using the
    // CoreUserInfoClaims type alias.
}

#[tracing::instrument(skip_all)]
pub async fn next<C: OIDCClaims>(
    client: CoreClientFromDiscovery,
    auth_verify: AuthVerify,
    auth_code: String,
) -> anyhow::Result<OIDCUser<C>> {
    // Once the user has been redirected to the redirect URL, you'll have access to the
    // authorization code. For security reasons, your code should verify that the `state`
    // parameter returned by the server matches `csrf_state`.

    // Now you can exchange it for an access token and ID token.
    let async_http_client = openidconnect::reqwest::Client::new();
    let token_response = client
        .exchange_code(AuthorizationCode::new(auth_code))?
        // Set the PKCE code verifier.
        .set_pkce_verifier(auth_verify.pkce_verifier)
        .request_async(&async_http_client)
        .await?;

    // Extract the ID token claims after verifying its authenticity and nonce.
    let id_token = token_response
        .id_token()
        .ok_or_else(|| anyhow!("Server did not return an ID token"))?;
    let claims = id_token.claims(&client.id_token_verifier(), &auth_verify.nonce)?;

    // Verify the access token hash to ensure that the access token hasn't been substituted for
    // another user's
    //
    let id_token_verifier = client.id_token_verifier();
    let verify_key = id_token.signing_key(&id_token_verifier)?;
    if let Some(expected_access_token_hash) = claims.access_token_hash() {
        let actual_access_token_hash =
            AccessTokenHash::from_token(
                token_response.access_token(),
                id_token.signing_alg()?,
                verify_key,


            )?;
        if actual_access_token_hash != *expected_access_token_hash {
            return Err(anyhow!("Invalid access token"));
        }
    }

    // The authenticated user's identity is now available. See the IdTokenClaims struct for a
    // complete listing of the available claims.
    // The user_info request uses the AccessToken returned in the token response. To parse custom
    // claims, use UserInfoClaims directly (with the desired type parameters) rather than using the
    // CoreUserInfoClaims type alias.
    let maybe_refresh_token = token_response.refresh_token();
    let userinfo_claims: UserInfoClaims<C, CoreGenderClaim> = client
        .user_info(token_response.access_token().to_owned(), None)
        .map_err(|err| anyhow!("No user info endpoint: {:?}", err))?
        .request_async(&async_http_client)
        .await
        .map_err(|err| anyhow!("Failed requesting user info: {:?}", err))?;
    tracing::debug!("Userinfo claims: {:?}", userinfo_claims);
    // If available, we can use the UserInfo endpoint to request additional information.
    return Ok(OIDCUser::from_claims(
        &userinfo_claims,
        maybe_refresh_token.cloned(),
        claims.expiration(),
    ));
}

pub fn router(auth_config: AuthConfig) -> axum::Router<AuthConfig> {
    router_with_claims::<GroupClaims>(auth_config)
}

pub fn router_with_claims<C: OIDCClaims + 'static>(auth_config: AuthConfig) -> axum::Router<AuthConfig>{
    let keyval = Key::try_from(auth_config.oidc_config.key.into_inner().as_bytes())
        .expect("Key must be >=64 bytes");
    KEY.set(keyval).ok();
    let r = Router::new()
        .route("/login", get(oidc_login))
        .route("/login_auth", get(login_auth::<C>));
    r

}
const COOKIE_NAME: &str = "auth_flow";
#[tracing::instrument(skip_all)]
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
        (StatusCode::UNAUTHORIZED, resp.into_string()).into_response()
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

#[tracing::instrument(skip_all)]
async fn login_auth<C: OIDCClaims + 'static>(
    State(config): State<AuthConfig>,
    cookies: Cookies,
    Query(oidc_auth_code): Query<OIDCAuthCode>,
) -> Result<Response, AuthError> {
    let auth_client = construct_client(config.clone()).await.unwrap();
    let key = KEY.get().unwrap();
    let private_cookies = cookies.private(key);
    let cookie = match private_cookies.get(COOKIE_NAME) {
        Some(c) => c,
        _ => return {
            tracing::info!(cookie_name= COOKIE_NAME, "Could not get cookie");
            Ok(StatusCode::UNAUTHORIZED.into_response())
        }
    };

    let cookie_str = cookie.value();
    let auth_verify: AuthVerify = serde_json::from_str(&cookie_str)?;

    if auth_verify.csrf_token.secret() != &oidc_auth_code.state {
        tracing::error!("CSRF State doesn't match");
        return Ok(StatusCode::UNAUTHORIZED.into_response());
    }

    let oidc_user: OIDCUser<C> = next::<C>(auth_client, auth_verify, oidc_auth_code.code).await?;
    save_user_to_cookies(&oidc_user, &private_cookies);

    Ok(Redirect::to(&config.post_auth_path).into_response())
}

fn save_user_to_cookies<C: OIDCClaims>(user: &OIDCUser<C>, jar: &tower_cookies::PrivateCookies) {
    let cookie_val_user = serde_json::to_string(&user).unwrap();
    let mut user_cookie = Cookie::new(USER_COOKIE_NAME, cookie_val_user);
    let max_age = user.expiration - chrono::Utc::now();
    let max_age_duration = tower_cookies::cookie::time::Duration::new(max_age.num_seconds(), 0);
    user_cookie.set_path("/");
    user_cookie.set_max_age(Some(max_age_duration));
    user_cookie.set_same_site(Some(tower_cookies::cookie::SameSite::Strict));
    user_cookie.set_secure(Some(true));
    user_cookie.set_http_only(Some(true));
    jar.add(user_cookie);

    let refresh_val = serde_json::to_string(&user.refresh_token).unwrap();
    let mut refresh_cookie = Cookie::new(REFRESH_COOKIE_NAME, refresh_val);
    refresh_cookie.set_path("/");
    refresh_cookie.set_max_age(Some(tower_cookies::cookie::time::Duration::new(86400, 0)));
    refresh_cookie.set_same_site(Some(tower_cookies::cookie::SameSite::Strict));
    refresh_cookie.set_secure(Some(true));
    refresh_cookie.set_http_only(Some(true));
    jar.add(refresh_cookie);
}
