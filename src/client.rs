use std::sync::Arc;

use base64::Engine;
use reqwest::{cookie::Jar, header, redirect, Url};
use rsa::{pkcs8::DecodePublicKey, RsaPublicKey};
use tracing::debug;

use crate::constants::{self, LOGIN_URL};

pub struct Client {
    pub client: reqwest::Client,
    pub cookie_jar: Arc<Jar>,
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Failed to decode RSA public key: {0}")]
    RsaPubKeyDecodeError(#[from] rsa::pkcs8::spki::Error),
    #[error("Failed to encrypt password: {0}")]
    RsaEncryptError(#[from] rsa::errors::Error),
    #[error("No url params found after redirect")]
    NoUrlParamsError,
    #[error(transparent)]
    ReqwestError(#[from] reqwest::Error),
    #[error("Param `{0}` not found in url parameters: ")]
    UrlParamsNotFoundError(String),
    #[error("Field not found in response json: {0}")]
    FieldNotFound(String),
}

pub type Result<T> = std::result::Result<T, Error>;

impl Client {
    /// Create a new client with custom headers and cookie enabled.
    ///
    /// Notice that `User-Agent` and `Referer` headers will be replaced to default values.
    pub fn with_headers(mut headers: header::HeaderMap) -> Self {
        headers.insert(header::USER_AGENT, constants::USER_AGENT.parse().unwrap());
        headers.insert(header::REFERER, constants::REFERER.parse().unwrap());

        let cookie_jar = Arc::new(Jar::default());

        let client = reqwest::Client::builder()
            .default_headers(headers)
            .cookie_provider(cookie_jar.clone())
            .redirect(redirect::Policy::limited(32))
            .build()
            .unwrap();

        Client { client, cookie_jar }
    }
    /// Create a new client with default headers and cookie enabled.
    ///
    /// Setted headers: `User-Agent` and `Referer`
    pub fn new() -> Self {
        let headers = reqwest::header::HeaderMap::new();
        Self::with_headers(headers)
    }
    /// Login with given session id.
    ///
    /// This function simply add a cookie to the cookie jar with the name `sessionid` and the value of `session_id`.
    ///
    /// And will NOT do any validations.
    pub fn login_with_cookie(&mut self, session_id: &str) {
        self.cookie_jar.add_cookie_str(format!("sessionid={}", session_id).as_str(), &Url::parse(constants::REFERER).unwrap());
    }
    /// Login with username and password.
    ///
    /// If login success, session id will be returned.
    pub async fn login(&self, username: &str, password: &str) -> Result<String> {
        debug!("Trying to login with username(= {}) and password", username);
        let client = &self.client;
        let response = client.get(constants::PRE_LOGIN_URL1).send().await?;
        let mut entity_id = None;
        let mut authn_lc_key = None;
        response.url().query_pairs()
            .for_each(|(key, value)| {
                let value = value.to_string();
                match &*key {
                    "entityId" => entity_id = Some(value),
                    "authnLcKey" => authn_lc_key = Some(value),
                    _ => (),
                }
            });
        let entity_id = entity_id.ok_or(Error::UrlParamsNotFoundError("entityId".to_string()))?;
        let authn_lc_key = authn_lc_key.ok_or(Error::UrlParamsNotFoundError("authnLcKey".to_string()))?;
        let encrypted_password = Self::encrypt_password(password)?;

        let _response = client.post(LOGIN_URL)
            .header("Referer", format!("https://iam.tongji.edu.cn/idp/authcenter/ActionAuthChain?entityId={}&authnLcKey={}", entity_id, authn_lc_key))
            .query(&[
                ("authnLcKey", authn_lc_key.clone()),
            ]).form(&[
                ("j_username", username),
                ("j_password", &encrypted_password),
                ("j_checkcode", "请输入验证码"),
                ("op", "login"),
                ("spAuthChainCode", constants::SP_AUTH_CHAIN_CODE),
                ("authnLcKey", &authn_lc_key),
            ]).send().await?;

        // make request to login and get redirect url
        let response = client.post(constants::LOGIN_URL2)
        .header("Referer", format!("https://iam.tongji.edu.cn/idp/authcenter/ActionAuthChain?entityId={}&authnLcKey={}", entity_id, authn_lc_key))
        .query(&[
            ("entityId", entity_id),
            ("currentAuth", constants::CURRENT_AUTH.to_string()),
            ("authnLcKey", authn_lc_key.clone()),
        ]).form(&[
            ("j_username", username),
            ("j_password", &encrypted_password),
            ("j_checkcode", "请输入验证码"),
            ("op", "login"),
            ("spAuthChainCode", constants::SP_AUTH_CHAIN_CODE),
            ("authnLcKey", &authn_lc_key),
        ]).send().await?;

        let (mut token, mut uid, mut ts) = (None, None, None);
        response.url().query_pairs().for_each(|(key, value)| {
            let value = value.to_string();
            match &*key {
                "token" => token = Some(value),
                "uid" => uid = Some(value),
                "ts" => ts = Some(value),
                _ => (),
            }
        });
        let token = token.ok_or(Error::UrlParamsNotFoundError("token".to_string()))?;
        let uid = uid.ok_or(Error::UrlParamsNotFoundError("uid".to_string()))?;
        let ts = ts.ok_or(Error::UrlParamsNotFoundError("ts".to_string()))?;
        debug!("token = {}, uid = {}, ts = {}", token, uid, ts);

        let response = client.post(constants::LOGIN_URL3)
            .header("Referer", format!("https://1.tongji.edu.cn/ssologin?token={}&uid={}&ts={}", token, uid, ts))
            .form(&[
                ("token", token),
                ("ts", ts),
                ("uid", uid)
            ]).send().await?.json::<serde_json::Value>().await?;
        let session_id = response.get("data")
            .and_then(|data| data.get("sessionid"))
            .and_then(|session_id| session_id.as_str())
            .ok_or(Error::FieldNotFound("data.sessionid".to_string()))?;
        debug!("session_id = {}", session_id);
        Ok(session_id.to_string())
    }

    fn encrypt_password(password: &str) -> Result<String> {
        let mut rng = rand::rngs::OsRng;
        let rsa_pub_key = RsaPublicKey::from_public_key_pem(&constants::RSA_PUB_KEY)?;
        let encrypted_password = rsa_pub_key.encrypt(&mut rng, rsa::Pkcs1v15Encrypt, &password.as_bytes())?;
        let result = base64::engine::general_purpose::STANDARD.encode(&encrypted_password);
        Ok(result)
    }
}