use std::borrow::Cow;
use std::str::from_utf8;
use std::marker::PhantomData;

use crate::code_grant::client_credentials::{
    client_credentials, Error as ClientCredentialsError, Extension,
    Endpoint as ClientCredentialsEndpoint, Request as ClientCredentialsRequest,
};
use crate::code_grant::error::{AccessTokenError, AccessTokenErrorType};
use crate::code_grant::refresh::ErrorDescription;
use crate::primitives::{registrar::Registrar, issuer::Issuer};
use super::{
    Endpoint, InnerTemplate, OAuthError, QueryParameter, WebRequest, WebResponse,
    is_authorization_method, OwnerConsent,
};

/// Offers access tokens to authenticated third parties.
///
/// A client may request a token that provides access to their own resources.
///
/// Client credentials can be allowed to appear in the request body instead of being
/// required to be passed as HTTP Basic authorization. This is not recommended and must be
/// enabled explicitely. See [`allow_credentials_in_body`] for details.
///
/// [`allow_credentials_in_body`]: #method.allow_credentials_in_body
pub struct ClientCredentialsFlow<E, R>
where
    E: Endpoint<R>,
    R: WebRequest,
{
    endpoint: WrappedToken<E, R>,
    allow_credentials_in_body: bool,
    allow_refresh_token: bool,
}

struct WrappedToken<E: Endpoint<R>, R: WebRequest> {
    inner: E,
    extension_fallback: (),
    r_type: PhantomData<R>,
}

struct WrappedRequest<'a, R: WebRequest + 'a> {
    /// Original request.
    request: PhantomData<R>,

    /// The request body
    body: Cow<'a, dyn QueryParameter + 'static>,

    /// The authorization tuple
    authorization: Option<Authorization>,

    /// An error if one occurred.
    error: Option<FailParse<R::Error>>,

    /// The credentials-in-body flag from the flow.
    allow_credentials_in_body: bool,
}

struct Invalid;

enum FailParse<E> {
    Invalid,
    Err(E),
}

struct Authorization(String, Vec<u8>);

impl<E, R> ClientCredentialsFlow<E, R>
where
    E: Endpoint<R>,
    R: WebRequest,
{
    /// Check that the endpoint supports the necessary operations for handling requests.
    ///
    /// Binds the endpoint to a particular type of request that it supports, for many
    /// implementations this is probably single type anyways.
    ///
    /// ## Panics
    ///
    /// Indirectly `execute` may panic when this flow is instantiated with an inconsistent
    /// endpoint, for details see the documentation of `Endpoint` and `execute`. For
    /// consistent endpoints, the panic is instead caught as an error here.
    pub fn prepare(mut endpoint: E) -> Result<Self, E::Error> {
        if endpoint.registrar().is_none() {
            return Err(endpoint.error(OAuthError::PrimitiveError));
        }

        if endpoint.issuer_mut().is_none() {
            return Err(endpoint.error(OAuthError::PrimitiveError));
        }

        Ok(ClientCredentialsFlow {
            endpoint: WrappedToken {
                inner: endpoint,
                extension_fallback: (),
                r_type: PhantomData,
            },
            allow_credentials_in_body: false,
            allow_refresh_token: false,
        })
    }

    /// Credentials in body should only be enabled if use of HTTP Basic is not possible.
    ///
    /// Allows the request body to contain the `client_secret` as a form parameter. This is NOT
    /// RECOMMENDED and need not be supported. The parameters MUST NOT appear in the request URI
    /// itself.
    ///
    /// Thus support is disabled by default and must be explicitely enabled.
    pub fn allow_credentials_in_body(&mut self, allow: bool) {
        self.allow_credentials_in_body = allow;
    }

    /// Allow the refresh token to be included in the response.
    ///
    /// According to [RFC-6749 Section 4.4.3][4.4.3] "A refresh token SHOULD NOT be included" in
    /// the response for the client credentials grant. Following that recommendation, the default
    /// behaviour of this flow is to discard any refresh token that is returned from the issuer.
    ///
    /// If this behaviour is not what you want (it is possible that your particular application
    /// does have a use for a client credentials refresh token), you may enable this feature.
    ///
    /// [4.4.3]: https://www.rfc-editor.org/rfc/rfc6749#section-4.4.3
    pub fn allow_refresh_token(&mut self, allow: bool) {
        self.allow_refresh_token = allow;
    }

    /// Use the checked endpoint to check for authorization for a resource.
    ///
    /// ## Panics
    ///
    /// When the registrar, authorizer, or issuer returned by the endpoint is suddenly
    /// `None` when previously it was `Some(_)`.
    pub fn execute(&mut self, mut request: R) -> Result<R::Response, E::Error> {
        let pending = client_credentials(
            &mut self.endpoint,
            &WrappedRequest::new(&mut request, self.allow_credentials_in_body),
        );
        let pending = match pending {
            Err(error) => {
                return client_credentials_error(&mut self.endpoint.inner, &mut request, error)
            }
            Ok(pending) => pending,
        };

        let consent = self
            .endpoint
            .inner
            .owner_solicitor()
            .unwrap()
            .check_consent(&mut request, pending.as_solicitation());

        let owner_id = match consent {
            OwnerConsent::Authorized(owner_id) => owner_id,
            OwnerConsent::Error(error) => return Err(self.endpoint.inner.web_error(error)),
            OwnerConsent::InProgress(..) => {
                // User interaction is not permitted in the client credentials flow, so
                // an InProgress response is invalid.
                return Err(self.endpoint.inner.error(OAuthError::PrimitiveError));
            }
            OwnerConsent::Denied => {
                let mut error = AccessTokenError::default();
                error.set_type(AccessTokenErrorType::InvalidClient);
                let mut json = ErrorDescription { error };
                let mut response = self.endpoint.inner.response(
                    &mut request,
                    InnerTemplate::Unauthorized {
                        error: None,
                        access_token_error: Some(json.description()),
                    }
                    .into(),
                )?;
                response
                    .client_error()
                    .map_err(|err| self.endpoint.inner.web_error(err))?;
                response
                    .body_json(&json.to_json())
                    .map_err(|err| self.endpoint.inner.web_error(err))?;
                return Ok(response);
            }
        };

        let token = match pending.issue(&mut self.endpoint, owner_id, self.allow_refresh_token) {
            Err(error) => {
                return client_credentials_error(&mut self.endpoint.inner, &mut request, error)
            }
            Ok(token) => token,
        };

        let mut response = self
            .endpoint
            .inner
            .response(&mut request, InnerTemplate::Ok.into())?;
        response
            .body_json(&token.to_json())
            .map_err(|err| self.endpoint.inner.web_error(err))?;
        Ok(response)
    }
}

fn client_credentials_error<E: Endpoint<R>, R: WebRequest>(
    endpoint: &mut E, request: &mut R, error: ClientCredentialsError,
) -> Result<R::Response, E::Error> {
    Ok(match error {
        ClientCredentialsError::Ignore => return Err(endpoint.error(OAuthError::DenySilently)),
        ClientCredentialsError::Invalid(mut json) => {
            let mut response = endpoint.response(
                request,
                InnerTemplate::BadRequest {
                    access_token_error: Some(json.description()),
                }
                .into(),
            )?;
            response.client_error().map_err(|err| endpoint.web_error(err))?;
            response
                .body_json(&json.to_json())
                .map_err(|err| endpoint.web_error(err))?;
            response
        }
        ClientCredentialsError::Unauthorized(mut json, scheme) => {
            let mut response = endpoint.response(
                request,
                InnerTemplate::Unauthorized {
                    error: None,
                    access_token_error: Some(json.description()),
                }
                .into(),
            )?;
            response
                .unauthorized(&scheme)
                .map_err(|err| endpoint.web_error(err))?;
            response
                .body_json(&json.to_json())
                .map_err(|err| endpoint.web_error(err))?;
            response
        }
        ClientCredentialsError::Primitive(_) => {
            // FIXME: give the context for restoration.
            return Err(endpoint.error(OAuthError::PrimitiveError));
        }
    })
}

impl<E: Endpoint<R>, R: WebRequest> ClientCredentialsEndpoint for WrappedToken<E, R> {
    fn registrar(&self) -> &dyn Registrar {
        self.inner.registrar().unwrap()
    }

    fn issuer(&mut self) -> &mut dyn Issuer {
        self.inner.issuer_mut().unwrap()
    }

    fn extension(&mut self) -> &mut dyn Extension {
        self.inner
            .extension()
            .and_then(super::Extension::client_credentials)
            .unwrap_or(&mut self.extension_fallback)
    }
}

impl<'a, R: WebRequest + 'a> WrappedRequest<'a, R> {
    pub fn new(request: &'a mut R, credentials: bool) -> Self {
        Self::new_or_fail(request, credentials).unwrap_or_else(Self::from_err)
    }

    fn new_or_fail(request: &'a mut R, credentials: bool) -> Result<Self, FailParse<R::Error>> {
        // If there is a header, it must parse correctly.
        let authorization = match request.authheader() {
            Err(err) => return Err(FailParse::Err(err)),
            Ok(Some(header)) => Self::parse_header(header).map(Some)?,
            Ok(None) => None,
        };

        Ok(WrappedRequest {
            request: PhantomData,
            body: request.urlbody().map_err(FailParse::Err)?,
            authorization,
            error: None,
            allow_credentials_in_body: credentials,
        })
    }

    fn from_err(err: FailParse<R::Error>) -> Self {
        WrappedRequest {
            request: PhantomData,
            body: Cow::Owned(Default::default()),
            authorization: None,
            error: Some(err),
            allow_credentials_in_body: false,
        }
    }

    fn parse_header(header: Cow<str>) -> Result<Authorization, Invalid> {
        let authorization = {
            let auth_data = match is_authorization_method(&header, "Basic ") {
                None => return Err(Invalid),
                Some(data) => data,
            };

            let combined = match base64::decode(auth_data) {
                Err(_) => return Err(Invalid),
                Ok(vec) => vec,
            };

            let mut split = combined.splitn(2, |&c| c == b':');
            let client_bin = match split.next() {
                None => return Err(Invalid),
                Some(client) => client,
            };
            let passwd = match split.next() {
                None => return Err(Invalid),
                Some(passwd64) => passwd64,
            };

            let client = match from_utf8(client_bin) {
                Err(_) => return Err(Invalid),
                Ok(client) => client,
            };

            Authorization(client.to_string(), passwd.to_vec())
        };

        Ok(authorization)
    }
}

impl<'a, R: WebRequest> ClientCredentialsRequest for WrappedRequest<'a, R> {
    fn valid(&self) -> bool {
        self.error.is_none()
    }

    fn authorization(&self) -> Option<(Cow<str>, Cow<[u8]>)> {
        self.authorization
            .as_ref()
            .map(|auth| (auth.0.as_str().into(), auth.1.as_slice().into()))
    }

    fn grant_type(&self) -> Option<Cow<str>> {
        self.body.unique_value("grant_type")
    }

    fn scope(&self) -> Option<Cow<str>> {
        self.body.unique_value("scope")
    }

    fn extension(&self, key: &str) -> Option<Cow<str>> {
        self.body.unique_value(key)
    }

    fn allow_credentials_in_body(&self) -> bool {
        self.allow_credentials_in_body
    }
}

impl<E> From<Invalid> for FailParse<E> {
    fn from(_: Invalid) -> Self {
        FailParse::Invalid
    }
}
