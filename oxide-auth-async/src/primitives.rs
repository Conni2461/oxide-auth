//! Async versions of all primitives traits.
use std::collections::HashMap;

use async_trait::async_trait;
use oxide_auth::primitives::prelude::Client;
use oxide_auth::primitives::registrar::EncodedClient;
use oxide_auth::primitives::{grant::Grant, scope::Scope};
use oxide_auth::primitives::issuer::{IssuedToken, RefreshedToken};
use oxide_auth::primitives::{
    authorizer, registrar, issuer,
    registrar::{ClientUrl, BoundClient, RegistrarError, PreGrant},
};
use url::Url;

#[async_trait]
pub trait Authorizer {
    async fn authorize(&mut self, _: Grant) -> Result<String, ()>;

    async fn extract(&mut self, _: &str) -> Result<Option<Grant>, ()>;
}

#[async_trait]
impl<T> Authorizer for T
where
    T: authorizer::Authorizer + Send + ?Sized,
{
    async fn authorize(&mut self, grant: Grant) -> Result<String, ()> {
        authorizer::Authorizer::authorize(self, grant)
    }

    async fn extract(&mut self, token: &str) -> Result<Option<Grant>, ()> {
        authorizer::Authorizer::extract(self, token)
    }
}

#[async_trait]
pub trait Issuer {
    async fn issue(&mut self, _: Grant) -> Result<IssuedToken, ()>;

    async fn refresh(&mut self, _: &str, _: Grant) -> Result<RefreshedToken, ()>;

    async fn recover_token(&mut self, _: &str) -> Result<Option<Grant>, ()>;

    async fn recover_refresh(&mut self, _: &str) -> Result<Option<Grant>, ()>;
}

#[async_trait]
impl<T> Issuer for T
where
    T: issuer::Issuer + Send + ?Sized,
{
    async fn issue(&mut self, grant: Grant) -> Result<IssuedToken, ()> {
        issuer::Issuer::issue(self, grant)
    }

    async fn refresh(&mut self, token: &str, grant: Grant) -> Result<RefreshedToken, ()> {
        issuer::Issuer::refresh(self, token, grant)
    }

    async fn recover_token(&mut self, token: &str) -> Result<Option<Grant>, ()> {
        issuer::Issuer::recover_token(self, token)
    }

    async fn recover_refresh(&mut self, token: &str) -> Result<Option<Grant>, ()> {
        issuer::Issuer::recover_refresh(self, token)
    }
}

#[async_trait]
pub trait Registrar {
    async fn bound_redirect<'a>(&self, bound: ClientUrl<'a>) -> Result<BoundClient<'a>, RegistrarError>;

    async fn negotiate<'a>(
        &self, client: BoundClient<'a>, scope: Option<Scope>,
    ) -> Result<PreGrant, RegistrarError>;

    async fn check(&self, client_id: &str, passphrase: Option<&[u8]>) -> Result<(), RegistrarError>;

    async fn register(&mut self, client: Client) -> Result<(), RegistrarError>;

    async fn query(&self, client_id: &str) -> Option<EncodedClient>;

    async fn query_by_extensions(&self, query: HashMap<String, String>) -> Vec<EncodedClient>;

    async fn add_uri(&mut self, client_id: &str, uri: Url) -> Result<(), RegistrarError>;

    async fn del_uri(&mut self, client_id: &str, uri: Url) -> Result<(), RegistrarError>;

    async fn del_client(&mut self, client_id: &str) -> Result<(), RegistrarError>;
}

#[async_trait]
impl<T> Registrar for T
where
    T: registrar::Registrar + Send + Sync + ?Sized,
{
    async fn bound_redirect<'a>(&self, bound: ClientUrl<'a>) -> Result<BoundClient<'a>, RegistrarError> {
        registrar::Registrar::bound_redirect(self, bound)
    }

    async fn negotiate<'a>(
        &self, client: BoundClient<'a>, scope: Option<Scope>,
    ) -> Result<PreGrant, RegistrarError> {
        registrar::Registrar::negotiate(self, client, scope)
    }

    async fn check(&self, client_id: &str, passphrase: Option<&[u8]>) -> Result<(), RegistrarError> {
        registrar::Registrar::check(self, client_id, passphrase)
    }

    async fn register(&mut self, client: Client) -> Result<(), RegistrarError> {
        registrar::Registrar::register(self, client)
    }

    /// Get a encoded client record.
    async fn query(&self, client_id: &str) -> Option<EncodedClient> {
        registrar::Registrar::query(self, client_id)
    }

    async fn query_by_extensions(&self, query: HashMap<String, String>) -> Vec<EncodedClient> {
        registrar::Registrar::query_by_extensions(self, query)
    }

    async fn add_uri(&mut self, client_id: &str, uri: Url) -> Result<(), RegistrarError> {
        registrar::Registrar::add_uri(self, client_id, uri)
    }

    async fn del_uri(&mut self, client_id: &str, uri: Url) -> Result<(), RegistrarError> {
        registrar::Registrar::add_uri(self, client_id, uri)
    }

    async fn del_client(&mut self, client_id: &str) -> Result<(), RegistrarError> {
        registrar::Registrar::del_client(self, client_id)
    }
}
