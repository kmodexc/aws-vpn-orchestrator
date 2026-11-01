//! JWT validation for Keycloak access tokens (SPEC §4.2) and ID tokens (SPEC §4.1).
//!
//! These functions are pure: they take the key set as a parameter. Fetching and caching the
//! JWKS lives in [`super::oidc`].

use std::collections::{BTreeSet, HashMap};

use jsonwebtoken::jwk::{AlgorithmParameters, EllipticCurve, Jwk, JwkSet, PublicKeyUse};
use jsonwebtoken::{Algorithm, DecodingKey, Header, Validation, decode, decode_header};
use serde::Deserialize;

use crate::util::ct_eq_str;

/// Only asymmetric algorithms that Keycloak uses. `none` cannot even be parsed and HS* are
/// rejected here, which rules out algorithm-confusion attacks.
pub const ALLOWED_ALGORITHMS: [Algorithm; 3] =
    [Algorithm::RS256, Algorithm::ES256, Algorithm::PS256];
pub const LEEWAY_S: u64 = 30;
const MAX_TOKEN_LEN: usize = 16 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum JwtError {
    #[error("malformed token")]
    Malformed,
    #[error("algorithm not allowed")]
    AlgorithmNotAllowed,
    /// No key with this `kid` in the current JWKS; the caller may refresh the JWKS and retry.
    #[error("unknown signing key")]
    UnknownKey,
    #[error("invalid token: {0}")]
    Invalid(String),
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct RoleSet {
    #[serde(default)]
    pub roles: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AccessClaims {
    pub iss: String,
    pub exp: i64,
    #[serde(default)]
    pub sub: Option<String>,
    #[serde(default)]
    pub typ: Option<String>,
    #[serde(default)]
    pub azp: Option<String>,
    #[serde(default)]
    pub preferred_username: Option<String>,
    #[serde(default)]
    pub email: Option<String>,
    #[serde(default)]
    pub realm_access: Option<RoleSet>,
    #[serde(default)]
    pub resource_access: Option<HashMap<String, RoleSet>>,
}

impl AccessClaims {
    /// SPEC §4.3: the role is in `realm_access.roles` or `resource_access.<client_id>.roles`.
    /// Production code decides through [`roles`](Self::roles) (`auth::access_of`); this is
    /// kept for the claim-parsing tests.
    #[cfg(test)]
    pub fn has_role(&self, role: &str, client_id: &str) -> bool {
        let realm = self
            .realm_access
            .as_ref()
            .is_some_and(|r| r.roles.iter().any(|x| x == role));
        let client = self
            .resource_access
            .as_ref()
            .and_then(|m| m.get(client_id))
            .is_some_and(|r| r.roles.iter().any(|x| x == role));
        realm || client
    }

    /// Realm roles plus the roles of `client_id`, sorted and de-duplicated.
    pub fn roles(&self, client_id: &str) -> Vec<String> {
        let mut set = BTreeSet::new();
        if let Some(r) = &self.realm_access {
            set.extend(r.roles.iter().cloned());
        }
        if let Some(r) = self.resource_access.as_ref().and_then(|m| m.get(client_id)) {
            set.extend(r.roles.iter().cloned());
        }
        set.into_iter().collect()
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum Audience {
    One(String),
    Many(Vec<String>),
}

impl Audience {
    fn len(&self) -> usize {
        match self {
            Self::One(_) => 1,
            Self::Many(v) => v.len(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct IdClaims {
    pub iss: String,
    pub sub: String,
    pub aud: Audience,
    pub exp: i64,
    #[serde(default)]
    pub nonce: Option<String>,
    #[serde(default)]
    pub azp: Option<String>,
    #[serde(default)]
    pub typ: Option<String>,
    #[serde(default)]
    pub preferred_username: Option<String>,
    #[serde(default)]
    pub email: Option<String>,
}

/// Parse a JWKS document leniently: keys that cannot be represented (unknown algorithms,
/// encryption keys, …) are skipped instead of failing the whole set.
pub fn parse_jwks(bytes: &[u8]) -> Result<JwkSet, serde_json::Error> {
    #[derive(Deserialize)]
    struct RawSet {
        keys: Vec<serde_json::Value>,
    }
    let raw: RawSet = serde_json::from_slice(bytes)?;
    let keys = raw
        .keys
        .into_iter()
        .filter_map(|k| serde_json::from_value::<Jwk>(k).ok())
        .collect();
    Ok(JwkSet { keys })
}

fn header_of(token: &str) -> Result<Header, JwtError> {
    if token.is_empty() || token.len() > MAX_TOKEN_LEN {
        return Err(JwtError::Malformed);
    }
    let header = decode_header(token).map_err(|_| JwtError::Malformed)?;
    if !ALLOWED_ALGORITHMS.contains(&header.alg) {
        return Err(JwtError::AlgorithmNotAllowed);
    }
    if header.crit.is_some() {
        return Err(JwtError::Invalid("unsupported crit header".into()));
    }
    Ok(header)
}

/// Offline structural check of a token (size, header, allowed algorithm, `kid` present). It
/// needs no keys, so callers run it **before** fetching discovery/JWKS: garbage, `none` and HS*
/// tokens are rejected (and counted as failures) even while the IdP is unreachable, and they
/// never trigger outbound requests.
pub fn precheck(token: &str) -> Result<(), JwtError> {
    let header = header_of(token)?;
    if header.kid.as_deref().is_none_or(str::is_empty) {
        return Err(JwtError::Invalid("missing kid".into()));
    }
    Ok(())
}

/// Pick the verification key for a token header, checking that the key type, curve, `use` and
/// `alg` of the JWK are consistent with the header's algorithm.
fn select_key(jwks: &JwkSet, header: &Header) -> Result<DecodingKey, JwtError> {
    let kid = header
        .kid
        .as_deref()
        .ok_or(JwtError::Invalid("missing kid".into()))?;
    let jwk = jwks.find(kid).ok_or(JwtError::UnknownKey)?;
    if let Some(usage) = &jwk.common.public_key_use {
        if *usage != PublicKeyUse::Signature {
            return Err(JwtError::Invalid("key is not a signing key".into()));
        }
    }
    if let Some(alg) = jwk.common.key_algorithm {
        if alg.to_string() != format!("{:?}", header.alg) {
            return Err(JwtError::Invalid("key algorithm mismatch".into()));
        }
    }
    let family_ok = match (&jwk.algorithm, header.alg) {
        (AlgorithmParameters::RSA(_), Algorithm::RS256 | Algorithm::PS256) => true,
        (AlgorithmParameters::EllipticCurve(p), Algorithm::ES256) => p.curve == EllipticCurve::P256,
        _ => false,
    };
    if !family_ok {
        return Err(JwtError::Invalid(
            "key type does not match algorithm".into(),
        ));
    }
    DecodingKey::from_jwk(jwk).map_err(|e| JwtError::Invalid(format!("bad key: {:?}", e.kind())))
}

fn base_validation(alg: Algorithm, issuer: &str) -> Validation {
    let mut v = Validation::new(alg);
    v.algorithms = vec![alg];
    v.leeway = LEEWAY_S;
    v.validate_exp = true;
    v.validate_nbf = true;
    v.set_issuer(&[issuer]);
    v
}

/// Validate a Keycloak access token: signature, `iss`, `exp`/`nbf` (30 s leeway), `typ` ==
/// `Bearer` when present and `azp` ∈ `allowed_azp`.
pub fn validate_access_token(
    token: &str,
    jwks: &JwkSet,
    issuer: &str,
    allowed_azp: &[String],
) -> Result<AccessClaims, JwtError> {
    let header = header_of(token)?;
    let key = select_key(jwks, &header)?;
    let mut validation = base_validation(header.alg, issuer);
    validation.validate_aud = false;
    validation.set_required_spec_claims(&["exp", "iss"]);
    let claims = decode::<AccessClaims>(token, &key, &validation)
        .map_err(|e| JwtError::Invalid(format!("{:?}", e.kind())))?
        .claims;
    if let Some(typ) = &claims.typ {
        if typ != "Bearer" {
            return Err(JwtError::Invalid("typ is not Bearer".into()));
        }
    }
    match &claims.azp {
        Some(azp) if allowed_azp.iter().any(|a| a == azp) => {}
        _ => return Err(JwtError::Invalid("azp not allowed".into())),
    }
    Ok(claims)
}

/// Validate an OIDC ID token: signature, `iss`, `aud` contains `client_id`, `exp`/`nbf`,
/// `azp` (when present or when there are several audiences) and the `nonce`.
pub fn validate_id_token(
    token: &str,
    jwks: &JwkSet,
    issuer: &str,
    client_id: &str,
    expected_nonce: &str,
) -> Result<IdClaims, JwtError> {
    let header = header_of(token)?;
    let key = select_key(jwks, &header)?;
    let mut validation = base_validation(header.alg, issuer);
    validation.validate_aud = true;
    validation.set_audience(&[client_id]);
    validation.set_required_spec_claims(&["exp", "iss", "aud", "sub"]);
    let claims = decode::<IdClaims>(token, &key, &validation)
        .map_err(|e| JwtError::Invalid(format!("{:?}", e.kind())))?
        .claims;
    if claims.aud.len() > 1 && claims.azp.is_none() {
        return Err(JwtError::Invalid(
            "azp required with multiple audiences".into(),
        ));
    }
    if let Some(azp) = &claims.azp {
        if azp != client_id {
            return Err(JwtError::Invalid("azp mismatch".into()));
        }
    }
    if let Some(typ) = &claims.typ {
        if typ != "ID" {
            return Err(JwtError::Invalid("typ is not ID".into()));
        }
    }
    match &claims.nonce {
        Some(n) if ct_eq_str(n, expected_nonce) => {}
        _ => return Err(JwtError::Invalid("nonce mismatch".into())),
    }
    Ok(claims)
}

#[cfg(test)]
pub(crate) mod test_keys {
    //! Test-only signing keys and a token factory.

    use super::*;
    use jsonwebtoken::jwk::{CommonParameters, KeyAlgorithm};
    use jsonwebtoken::{EncodingKey, encode};
    use std::sync::OnceLock;

    pub const ISSUER: &str = "https://auth.kmode.dev/realms/test";
    pub const CLIENT: &str = "vpn-control";
    pub const KID: &str = "test-rsa";

    pub struct TestKey {
        pub encoding: EncodingKey,
        pub jwk: Jwk,
    }

    /// A freshly generated RSA-2048 key (generated once per test process).
    pub fn rsa() -> &'static TestKey {
        static KEY: OnceLock<TestKey> = OnceLock::new();
        KEY.get_or_init(|| {
            let kp = rcgen::KeyPair::generate_for(&rcgen::PKCS_RSA_SHA256).unwrap();
            let encoding = EncodingKey::from_rsa_pem(kp.serialize_pem().as_bytes()).unwrap();
            let mut jwk = Jwk::from_encoding_key(&encoding, Algorithm::RS256).unwrap();
            jwk.common = CommonParameters {
                key_id: Some(KID.into()),
                key_algorithm: Some(KeyAlgorithm::RS256),
                public_key_use: Some(PublicKeyUse::Signature),
                ..Default::default()
            };
            TestKey { encoding, jwk }
        })
    }

    pub fn jwks() -> JwkSet {
        JwkSet {
            keys: vec![rsa().jwk.clone()],
        }
    }

    pub fn now() -> i64 {
        crate::util::unix_now()
    }

    pub fn access_claims() -> serde_json::Value {
        serde_json::json!({
            "iss": ISSUER,
            "sub": "user-1",
            "exp": now() + 300,
            "iat": now(),
            "typ": "Bearer",
            "azp": CLIENT,
            "preferred_username": "alice",
            "email": "alice@example.com",
            "realm_access": {"roles": ["offline_access", "vpn-admin"]},
            "resource_access": {"account": {"roles": ["view-profile"]}},
        })
    }

    pub fn sign(claims: &serde_json::Value) -> String {
        sign_with(claims, Algorithm::RS256, Some(KID), &rsa().encoding)
    }

    pub fn sign_with(
        claims: &serde_json::Value,
        alg: Algorithm,
        kid: Option<&str>,
        key: &EncodingKey,
    ) -> String {
        let mut header = Header::new(alg);
        header.kid = kid.map(str::to_string);
        encode(&header, claims, key).unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::test_keys::*;
    use super::*;
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use jsonwebtoken::EncodingKey;

    fn allowed() -> Vec<String> {
        vec![CLIENT.to_string()]
    }

    fn check(claims: &serde_json::Value) -> Result<AccessClaims, JwtError> {
        validate_access_token(&sign(claims), &jwks(), ISSUER, &allowed())
    }

    #[test]
    fn valid_access_token() {
        let c = check(&access_claims()).unwrap();
        assert_eq!(c.sub.as_deref(), Some("user-1"));
        assert!(c.has_role("vpn-admin", CLIENT));
        assert_eq!(c.roles(CLIENT), vec!["offline_access", "vpn-admin"]);
    }

    #[test]
    fn rejects_alg_none() {
        let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"none","typ":"JWT","kid":"test-rsa"}"#);
        let payload = URL_SAFE_NO_PAD.encode(access_claims().to_string());
        for token in [
            format!("{header}.{payload}."),
            format!("{header}.{payload}"),
        ] {
            let err = validate_access_token(&token, &jwks(), ISSUER, &allowed()).unwrap_err();
            assert_eq!(err, JwtError::Malformed);
        }
    }

    #[test]
    fn rejects_hs256_even_with_public_key_as_secret() {
        // Classic algorithm confusion: HMAC keyed with the RSA public modulus.
        let AlgorithmParameters::RSA(rsa_params) = &rsa().jwk.algorithm else {
            panic!("expected RSA key");
        };
        let key = EncodingKey::from_secret(rsa_params.n.as_bytes());
        let token = sign_with(&access_claims(), Algorithm::HS256, Some(KID), &key);
        let err = validate_access_token(&token, &jwks(), ISSUER, &allowed()).unwrap_err();
        assert_eq!(err, JwtError::AlgorithmNotAllowed);
    }

    #[test]
    fn rejects_wrong_issuer() {
        let mut c = access_claims();
        c["iss"] = "https://evil.example.com/realms/test".into();
        assert!(matches!(check(&c), Err(JwtError::Invalid(_))));
        c["iss"] = format!("{ISSUER}/").into();
        assert!(matches!(check(&c), Err(JwtError::Invalid(_))));
    }

    #[test]
    fn rejects_expired_and_respects_leeway() {
        let mut c = access_claims();
        c["exp"] = (now() - 120).into();
        assert!(matches!(check(&c), Err(JwtError::Invalid(_))));
        c["exp"] = (now() - 10).into();
        assert!(check(&c).is_ok(), "within 30 s leeway");
        let mut c = access_claims();
        c["nbf"] = (now() + 600).into();
        assert!(matches!(check(&c), Err(JwtError::Invalid(_))));
        let mut c = access_claims();
        c.as_object_mut().unwrap().remove("exp");
        assert!(check(&c).is_err());
    }

    #[test]
    fn missing_role_is_detected() {
        let mut c = access_claims();
        c["realm_access"] = serde_json::json!({"roles": ["other"]});
        let claims = check(&c).unwrap();
        assert!(!claims.has_role("vpn-admin", CLIENT));
        // client role of OUR client counts
        c["resource_access"] = serde_json::json!({CLIENT: {"roles": ["vpn-admin"]}});
        assert!(check(&c).unwrap().has_role("vpn-admin", CLIENT));
        // client role of ANOTHER client does not
        c["resource_access"] = serde_json::json!({"other-client": {"roles": ["vpn-admin"]}});
        assert!(!check(&c).unwrap().has_role("vpn-admin", CLIENT));
    }

    #[test]
    fn rejects_wrong_or_missing_azp() {
        let mut c = access_claims();
        c["azp"] = "some-other-client".into();
        assert!(matches!(check(&c), Err(JwtError::Invalid(_))));
        c.as_object_mut().unwrap().remove("azp");
        assert!(matches!(check(&c), Err(JwtError::Invalid(_))));
        // allowed when configured
        let mut c = access_claims();
        c["azp"] = "android-app".into();
        let ok = validate_access_token(
            &sign(&c),
            &jwks(),
            ISSUER,
            &[CLIENT.to_string(), "android-app".to_string()],
        );
        assert!(ok.is_ok());
    }

    #[test]
    fn rejects_wrong_typ() {
        let mut c = access_claims();
        c["typ"] = "Refresh".into();
        assert!(matches!(check(&c), Err(JwtError::Invalid(_))));
        c.as_object_mut().unwrap().remove("typ");
        assert!(check(&c).is_ok(), "typ is optional");
    }

    #[test]
    fn rejects_unknown_kid_bad_signature_and_garbage() {
        let token = sign_with(
            &access_claims(),
            Algorithm::RS256,
            Some("other"),
            &rsa().encoding,
        );
        assert_eq!(
            validate_access_token(&token, &jwks(), ISSUER, &allowed()).unwrap_err(),
            JwtError::UnknownKey
        );
        let token = sign_with(&access_claims(), Algorithm::RS256, None, &rsa().encoding);
        assert!(validate_access_token(&token, &jwks(), ISSUER, &allowed()).is_err());

        // tamper with the payload
        let token = sign(&access_claims());
        let mut parts: Vec<String> = token.split('.').map(str::to_string).collect();
        let mut c = access_claims();
        c["realm_access"] = serde_json::json!({"roles": ["vpn-admin", "superuser"]});
        parts[1] = URL_SAFE_NO_PAD.encode(c.to_string());
        let forged = parts.join(".");
        assert!(matches!(
            validate_access_token(&forged, &jwks(), ISSUER, &allowed()),
            Err(JwtError::Invalid(_))
        ));

        for garbage in ["", "abc", "a.b.c", "....."] {
            assert!(validate_access_token(garbage, &jwks(), ISSUER, &allowed()).is_err());
        }
    }

    #[test]
    fn precheck_rejects_without_keys() {
        assert!(precheck(&sign(&access_claims())).is_ok());
        for garbage in ["", "abc", "abc.def.ghi", "....."] {
            assert_eq!(precheck(garbage), Err(JwtError::Malformed), "{garbage}");
        }
        let AlgorithmParameters::RSA(rsa_params) = &rsa().jwk.algorithm else {
            panic!("expected RSA key");
        };
        let hs = sign_with(
            &access_claims(),
            Algorithm::HS256,
            Some(KID),
            &EncodingKey::from_secret(rsa_params.n.as_bytes()),
        );
        assert_eq!(precheck(&hs), Err(JwtError::AlgorithmNotAllowed));
        let no_kid = sign_with(&access_claims(), Algorithm::RS256, None, &rsa().encoding);
        assert!(matches!(precheck(&no_kid), Err(JwtError::Invalid(_))));
    }

    #[test]
    fn rejects_key_algorithm_mismatch() {
        // header says PS256 but the JWK is pinned to RS256
        let token = sign_with(
            &access_claims(),
            Algorithm::PS256,
            Some(KID),
            &rsa().encoding,
        );
        assert!(matches!(
            validate_access_token(&token, &jwks(), ISSUER, &allowed()),
            Err(JwtError::Invalid(_))
        ));
    }

    fn id_claims() -> serde_json::Value {
        serde_json::json!({
            "iss": ISSUER,
            "sub": "user-1",
            "aud": CLIENT,
            "azp": CLIENT,
            "exp": now() + 300,
            "iat": now(),
            "typ": "ID",
            "nonce": "the-nonce",
            "preferred_username": "alice",
        })
    }

    #[test]
    fn id_token_validation() {
        let ok = validate_id_token(&sign(&id_claims()), &jwks(), ISSUER, CLIENT, "the-nonce");
        assert_eq!(ok.unwrap().sub, "user-1");

        let wrong_nonce = validate_id_token(&sign(&id_claims()), &jwks(), ISSUER, CLIENT, "other");
        assert!(wrong_nonce.is_err());

        let mut c = id_claims();
        c["aud"] = "someone-else".into();
        assert!(validate_id_token(&sign(&c), &jwks(), ISSUER, CLIENT, "the-nonce").is_err());

        let mut c = id_claims();
        c["aud"] = serde_json::json!([CLIENT, "x"]);
        c.as_object_mut().unwrap().remove("azp");
        assert!(validate_id_token(&sign(&c), &jwks(), ISSUER, CLIENT, "the-nonce").is_err());

        let mut c = id_claims();
        c.as_object_mut().unwrap().remove("nonce");
        assert!(validate_id_token(&sign(&c), &jwks(), ISSUER, CLIENT, "the-nonce").is_err());

        let mut c = id_claims();
        c["exp"] = (now() - 100).into();
        assert!(validate_id_token(&sign(&c), &jwks(), ISSUER, CLIENT, "the-nonce").is_err());
    }

    #[test]
    fn lenient_jwks_parsing_skips_unknown_keys() {
        let mut doc = serde_json::to_value(jwks()).unwrap();
        doc["keys"]
            .as_array_mut()
            .unwrap()
            .push(serde_json::json!({"kty": "weird", "kid": "x", "alg": "FOO-1"}));
        let parsed = parse_jwks(doc.to_string().as_bytes()).unwrap();
        assert!(parsed.find(KID).is_some());
    }
}
