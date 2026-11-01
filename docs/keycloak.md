# Keycloak setup (https://auth.kmode.dev)

vpn-control authenticates against Keycloak with OpenID Connect. This guide uses the current
Keycloak admin console (Keycloak 26.x; menu names may differ slightly in other versions).
Throughout, replace:

- `<realm>` — the realm you use (e.g. `kmode`)
- `<DOMAIN>` — the control-plane host name from `.env` (e.g. `vpn.kmode.dev`)

Admin console: `https://auth.kmode.dev/admin/` → select `<realm>` in the realm dropdown
(top-left). Do **not** use the `master` realm for end users.

## 1. Realm settings (security baseline)

*Realm settings*:

| Tab | Setting | Value |
|---|---|---|
| General | Require SSL | **all requests** |
| Login | User registration | **Off** |
| Login | Forgot password / Remember me | your choice (Remember me: Off recommended) |
| Login | Email as username / Login with email | your choice |
| Tokens | Default signature algorithm | **RS256** (or ES256/PS256 — HS* is rejected by vpn-control) |
| Tokens | Access Token Lifespan | **5 minutes** |
| Sessions | SSO Session Idle | 30 minutes |
| Sessions | SSO Session Max | 10 hours |
| Security defenses → Brute force detection | Brute Force Mode | **Lockout temporarily** (e.g. max login failures 5, wait increment 1 min, max wait 15 min, failure reset 12 h) |
| Security defenses → Headers | keep the defaults (X-Frame-Options, CSP frame-ancestors) | |

The backend keeps its own session (idle 30 min / absolute 12 h by default, see
`SESSION_*` in `.env`) and only uses the access token at login time, so short access-token
lifetimes cost nothing.

The **issuer** of the realm is `https://auth.kmode.dev/realms/<realm>`. Verify it — it must match
`OIDC_ISSUER_URL` exactly (no trailing slash):

```bash
curl -s https://auth.kmode.dev/realms/<realm>/.well-known/openid-configuration | grep '"issuer"'
```

If the issuer shows an internal host name or `http://`, Keycloak's hostname configuration
(`KC_HOSTNAME`, proxy headers) is wrong — fix that first.

## 2. Realm role `vpn-admin`

*Realm roles* → **Create role** → Role name `vpn-admin` → Save.

Only users with this role may use vpn-control (`OIDC_REQUIRED_ROLE`, default `vpn-admin`). A user
who logs in without it gets *"Your account lacks the required role"* (HTTP 403).

> Alternatively use a **client role** of the web client (*Clients → console → Roles*); the
> backend accepts `OIDC_REQUIRED_ROLE` from `realm_access.roles` **or**
> `resource_access.<OIDC_CLIENT_ID>.roles`. Use a realm role if you also use the Android client,
> because client roles of `console` are not automatically present in the Android client's tokens.

## 3. Web client (confidential, used by the backend)

*Clients* → **Create client**

**Step 1 — General settings**

- Client type: **OpenID Connect**
- Client ID: `console` (→ `OIDC_CLIENT_ID`)
- Name: `Console`
- Always display in UI: Off

**Step 2 — Capability config**

- Client authentication: **On** (confidential client)
- Authorization: Off
- Authentication flow:
  - Standard flow: **On**
  - Direct access grants: **Off**
  - Implicit flow: **Off**
  - Service accounts roles: **Off**
  - OAuth 2.0 Device Authorization Grant: **Off**
  - OIDC CIBA Grant: **Off**
- PKCE Method: **S256** (if this option is not on this page in your version, set it in step 4)

**Step 3 — Login settings**

- Root URL: `https://<DOMAIN>`
- Home URL: `https://<DOMAIN>/`
- Valid redirect URIs: exactly **`https://<DOMAIN>/auth/callback`** — no wildcards
- Valid post logout redirect URIs: exactly **`https://<DOMAIN>/`**
- Web origins: **leave empty** (or `-`). vpn-control does no CORS; the browser never talks to
  Keycloak from JavaScript.

→ **Save**.

**Step 4 — Advanced / other tabs of the new client**

- *Advanced → Advanced settings*: **Proof Key for Code Exchange Code Challenge Method = S256**
  (Keycloak then rejects authorization requests without PKCE).
- *Settings → Login settings*: Consent required **Off**.
- *Settings → Logout settings*: Front channel logout **Off**, Backchannel logout URL empty
  (vpn-control destroys its own session on logout and redirects to Keycloak's end-session
  endpoint).
- *Credentials*: Client Authenticator **Client Id and Secret**. Copy the **Client secret** →
  `OIDC_CLIENT_SECRET`. (Regenerate it here when rotating; see docs/security.md.)

**Recommended — minimal token contents**

*Client scopes* tab → `console-dedicated` → *Scope* tab → **Full scope allowed: Off** →
**Assign role** → filter by realm roles → `vpn-admin`. Tokens for this client then contain only
the `vpn-admin` role instead of every role the user has.

### Keep the sign-in neutral

Anyone who opens the control plane without a session sees only this Keycloak sign-in, so nothing
on it should hint at what is behind it:

- Client ID and name: neutral (`console` / `Console`). They appear in the login URL
  (`client_id=…`) and in the account console. An existing client can be renamed in
  *Clients → <client> → Settings → Client ID*; then set `OIDC_CLIENT_ID` (and
  `OIDC_ALLOWED_CLIENTS`) in `.env` to the new id and restart the app. Client roles move with
  the client.
- *Realm settings → General → Display name* / *HTML Display name*: neutral, or empty.
- Login theme: the default, or a neutral one — no VPN wording or icons.

## 4. Make sure the role is in the access token

The backend reads roles from the **access token** (`realm_access.roles` /
`resource_access.<client>.roles`). Keycloak puts them there through the default client scope
**`roles`**:

- *Clients → console → Client scopes*: `roles` must be listed as **Default**
  (it is by default). Also keep `profile`, `email` default (or adjust `OIDC_SCOPES`).
- *Client scopes → roles → Mappers → realm roles*: **Add to access token = On**.

Verify: *Clients → console → Client scopes → Evaluate* → pick your user →
**Generated access token**. You must see

```json
"azp": "console",
"realm_access": { "roles": ["vpn-admin"] },
"typ": "Bearer"
```

## 5. Your user

*Users* → your user (or **Add user**):

- Email verified: On
- *Role mapping* → **Assign role** → filter by realm roles → `vpn-admin`
- *Credentials*: set a strong password (Temporary: Off) if the user has none
- **Second factor (strongly recommended — this account can control your VPN):**
  - *Details* → Required user actions → **Configure OTP** (TOTP app), and/or
  - **Webauthn Register Passwordless** / **Webauthn Register** for a passkey / security key
    (enable the corresponding required actions under *Authentication → Required actions* first).
  The default browser flow asks for OTP whenever the user has OTP configured. To require 2FA for
  everyone in the realm, set *Authentication → Flows → browser → Browser - Conditional OTP* to
  **Required**.

## 6. Optional: Android (or other native) client

Native apps cannot keep a secret, so they use a **public** client with PKCE and send the
resulting access token as `Authorization: Bearer …`.

*Clients* → **Create client**

- Client type OpenID Connect, Client ID e.g. `console-android`
- Client authentication: **Off** (public)
- Standard flow **On**; Direct access grants, Implicit, Device grant: **Off**
- PKCE Method / *Advanced* → Code Challenge Method: **S256**
- Valid redirect URIs: the app's redirect, e.g. a private-use scheme in reverse-DNS form
  `dev.kmode.vpncontrol:/oauth2redirect` (or a verified App Link `https://<DOMAIN>/app/callback`).
  No wildcards.
- Web origins: empty
- Recommended: Full scope allowed **Off** + scope mapping to realm role `vpn-admin` (as in §3).

Then allow its tokens in `.env`:

```ini
OIDC_ALLOWED_CLIENTS=console,console-android
```

and restart: `docker compose up -d`.

## 7. How vpn-control validates tokens (`azp` / `aud`)

See SPEC §4. In short:

- **Browser login** (web client): after the code exchange the backend verifies the **ID token**
  (signature via JWKS with RS256/ES256/PS256 only, `iss` = `OIDC_ISSUER_URL`, `aud` contains
  `OIDC_CLIENT_ID`, `exp`, `nonce`) and the **access token** with the same rules as Bearer tokens
  below, then checks the role. Tokens are kept server-side; the browser only gets an opaque
  session cookie.
- **Bearer tokens** (API clients): signature via JWKS (RS256/ES256/PS256; `none` and HS* are
  rejected), `iss` = `OIDC_ISSUER_URL`, `exp`/`nbf` (30 s leeway), `typ` = `Bearer` if present,
  and **`azp` ∈ `OIDC_ALLOWED_CLIENTS`**, then the role check.
- Why `azp` and not `aud`: Keycloak access tokens identify the client the token was issued *to*
  in `azp`; their `aud` is typically `account` (or absent) unless you add an audience mapper.
  Checking `azp` against an allow-list ensures that a token obtained by some *other* client of the
  realm (which the user might also be logged into) cannot be replayed against vpn-control, even if
  that user has the `vpn-admin` role. If you want `aud` to name vpn-control as well, add an
  *Audience* mapper (Included Client Audience = `console`, Add to access token = On) to the
  dedicated scopes — harmless, but not required.

## 8. Troubleshooting

| Symptom | Cause / fix |
|---|---|
| Keycloak shows *Invalid parameter: redirect_uri* | Valid redirect URIs must be exactly `https://<DOMAIN>/auth/callback` and `PUBLIC_BASE_URL` must be `https://<DOMAIN>`. |
| Back on the app with `login_error=unavailable` | The app cannot reach `OIDC_ISSUER_URL` (DNS/egress/TLS) — `docker compose logs app`. |
| `login_error=invalid` | Issuer mismatch (`OIDC_ISSUER_URL` vs. discovery `issuer`), wrong client secret, clock skew, or HS256 signing. |
| `login_error=forbidden` / "lacks the required role" | `vpn-admin` not assigned, not in the access token (§4), or Full scope Off without the scope mapping. |
| `login_error=denied` | The user cancelled or Keycloak denied the login. |
| Bearer requests get 401 | `azp` not in `OIDC_ALLOWED_CLIENTS`, expired token, or token from another realm. |
