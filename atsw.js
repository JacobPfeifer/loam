// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright (c) 2026 Jake Lazaroff https://tangled.org/jakelazaroff.com/atsw

/**
 * @typedef {Object} DPoPKey
 * @property {CryptoKey} privateKey
 * @property {JsonWebKey} jwk
 */

/**
 * @typedef {Object} OAuthConfig
 * @property {string} clientId
 * @property {string} redirectUri
 * @property {string} scope
 */

/**
 * @typedef {Object} AuthingSession
 * @property {string} state
 * @property {string} verifier
 * @property {DPoPKey} dpopKey
 * @property {string} tokenEndpoint
 * @property {string} issuer
 * @property {string} did
 * @property {string} pds
 * @property {OAuthConfig} config
 */

/**
 * @typedef {Object} OAuthSession
 * @property {string} pds
 * @property {string} did
 * @property {string} access_token
 * @property {string} token_type
 * @property {DPoPKey} dpopKey
 * @property {string} tokenEndpoint
 * @property {string} clientId
 * @property {number} expiresAt
 * @property {string} [refresh_token]
 * @property {string} [dpopNonce]
 */

/**
 * @typedef {Object} AuthServerMetadata
 * @property {string} issuer
 * @property {string} authorization_endpoint
 * @property {string} token_endpoint
 * @property {string} pushed_authorization_request_endpoint
 */

const enc = new TextEncoder();

/** @param {ArrayBuffer | Uint8Array} buf */
const b64url = (buf) =>
  btoa(String.fromCharCode(...new Uint8Array(buf)))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");

async function generatePKCE() {
  const verifier = b64url(crypto.getRandomValues(new Uint8Array(32)).buffer);
  const challenge = b64url(await crypto.subtle.digest("SHA-256", enc.encode(verifier)));
  return { verifier, challenge };
}

async function generateDPoPKey() {
  const { privateKey, publicKey } = await crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["sign"],
  );
  const { kty, crv, x, y } = await crypto.subtle.exportKey("jwk", publicKey);
  const jwk = { kty, crv, x, y };

  return { privateKey, jwk };
}

/**
 * @param {DPoPKey} dpopKey
 * @param {string} htm
 * @param {string} htu
 * @param {string} [nonce]
 * @param {string} [ath]
 */
async function createDPoP(dpopKey, htm, htu, nonce, ath) {
  const header = { alg: "ES256", typ: "dpop+jwt", jwk: dpopKey.jwk };

  const jti = b64url(crypto.getRandomValues(new Uint8Array(16)).buffer);

  /** @type {Record<string, string | number>} */
  const payload = { jti, htm, htu, iat: Math.floor(Date.now() / 1000) };
  if (nonce) payload["nonce"] = nonce;
  if (ath) payload["ath"] = ath;

  const toSign = [
    b64url(enc.encode(JSON.stringify(header)).buffer),
    b64url(enc.encode(JSON.stringify(payload)).buffer),
  ].join(".");

  const sig = await crypto.subtle.sign(
    { name: "ECDSA", hash: "SHA-256" },
    dpopKey.privateKey,
    enc.encode(toSign),
  );

  return toSign + "." + b64url(sig);
}

const MAX_DPOP_RETRIES = 2;

/**
 * @param {DPoPKey} key
 * @param {string} url
 * @param {URLSearchParams} body
 * @param {string} [nonce]
 * @returns {Promise<{ json: any, dpopNonce: string | undefined }>}
 */
async function dpopPost(key, url, body, nonce) {
  let dpopNonce = nonce;
  let lastRes;
  for (let attempts = 0; attempts < MAX_DPOP_RETRIES; attempts++) {
    const dpop = await createDPoP(key, "POST", url, dpopNonce);
    lastRes = await fetch(url, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded", DPoP: dpop },
      body,
    });
    dpopNonce = lastRes.headers.get("dpop-nonce") ?? dpopNonce;
    if (lastRes.ok || !lastRes.headers.get("dpop-nonce")) return { json: await lastRes.json(), dpopNonce };
  }

  return { json: await lastRes.json(), dpopNonce };
}

const DB_NAME = "atproto:oauth";
const DB_VERSION = 3;

/** @returns {Promise<IDBDatabase>} */
function openDb() {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, DB_VERSION);
    req.onupgradeneeded = () => {
      const db = req.result;
      if (!db.objectStoreNames.contains("authing"))
        db.createObjectStore("authing", { keyPath: "state" });

      if (db.objectStoreNames.contains("sessions")) db.deleteObjectStore("sessions");
      const ssns = db.createObjectStore("sessions", { keyPath: "did" });
      ssns.createIndex("pds", "pds", { unique: false });
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

/**
 * @param {IDBTransactionMode} mode
 * @param {string} store
 * @param {(s: IDBObjectStore) => IDBRequest} fn
 * @returns {Promise<any>}
 */
async function idb(mode, store, fn) {
  const db = await openDb();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(store, mode);
    const req = fn(tx.objectStore(store));
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

/** @param {AuthingSession} v */
const putAuthing = (v) => idb("readwrite", "authing", (s) => s.put(v));

/** @param {string} state @returns {Promise<AuthingSession | undefined>} */
const getAuthing = (state) => idb("readonly", "authing", (s) => s.get(state));

/** @param {string} state */
const deleteAuthing = (state) => idb("readwrite", "authing", (s) => s.delete(state));

/** @param {OAuthSession} v */
const putSession = (v) => idb("readwrite", "sessions", (s) => s.put(v));

/** @returns {Promise<OAuthSession[]>} */
export const listSessions = () => idb("readonly", "sessions", (s) => s.getAll());

/** @param {string} did @returns {Promise<OAuthSession | undefined>} */
export const getSession = (did) => idb("readonly", "sessions", (s) => s.get(did));

/** @param {string} pds @returns {Promise<OAuthSession[]>} */
const getSessionsByPDS = (pds) => idb("readonly", "sessions", (s) => s.index("pds").getAll(pds));

/** @param {string} did */
export const logOut = (did) => idb("readwrite", "sessions", (s) => s.delete(did));

/** @param {string} handle */
export async function resolveDID(handle) {
  try {
    const r = await fetch(`https://dns.google/resolve?name=_atproto.${handle}&type=TXT`);
    const j = await r.json();
    const txt = j.Answer?.find(/** @param {any} a */ (a) => a.data?.startsWith('"did='));
    if (txt) return /** @type {string} */ (txt.data.replace(/"/g, "").replace("did=", ""));
  } catch {}
  // HTTP .well-known resolution is blocked by CORS from the browser, so fall
  // back to the public AppView which exposes a CORS-enabled resolver.
  const r = await fetch(
    `https://public.api.bsky.app/xrpc/com.atproto.identity.resolveHandle?handle=${handle}`,
  );
  const j = await r.json();
  if (!j.did) throw new Error(`Could not resolve handle ${handle}: ${JSON.stringify(j)}`);
  return /** @type {string} */ (j.did);
}

/** @param {string} did */
async function resolvePDS(did) {
  const url = did.startsWith("did:web:")
    ? `https://${did.split(":")[2]}/.well-known/did.json`
    : `https://plc.directory/${did}`;
  const doc = await (await fetch(url)).json();
  const endpoint = doc.service?.find(
    /** @param {{type: string}} s */ (s) => s.type === "AtprotoPersonalDataServer",
  )?.serviceEndpoint;
  if (!endpoint) throw new Error(`No PDS found for ${did}`);
  return /** @type {string} */ (endpoint);
}

/**
 * @param {string} pds
 * @returns {Promise<AuthServerMetadata>}
 */
async function discoverAuthServer(pds) {
  const res = await (await fetch(`${pds}/.well-known/oauth-protected-resource`)).json();
  const issuer = /** @type {string} */ (res.authorization_servers[0]);
  return (await fetch(`${issuer}/.well-known/oauth-authorization-server`)).json();
}

/**
 * Fetch client metadata and return an OAuth config.
 * @param {string} metadataUrl
 * @returns {Promise<OAuthConfig>}
 */
export async function configure(metadataUrl) {
  const m = await (await fetch(metadataUrl)).json();
  return { clientId: m.client_id, redirectUri: m.redirect_uris[0], scope: m.scope };
}

/**
 * Start the OAuth login flow. Stores an authing session in IndexedDB and
 * redirects the browser to the authorization server. When the auth server
 * redirects back, the service worker will intercept the callback and complete
 * the token exchange.
 * @param {OAuthConfig} config
 * @param {string} handle
 * @returns {Promise<void>}
 */
export async function logIn(config, handle) {
  const did = await resolveDID(handle);
  const pds = await resolvePDS(did);
  const meta = await discoverAuthServer(pds);

  const pkce = await generatePKCE();
  const dpopKey = await generateDPoPKey();
  const state = b64url(crypto.getRandomValues(new Uint8Array(16)).buffer);

  await putAuthing({
    state,
    verifier: pkce.verifier,
    dpopKey,
    tokenEndpoint: meta.token_endpoint,
    issuer: meta.issuer,
    did,
    pds: new URL(pds).origin,
    config,
  });

  const parBody = new URLSearchParams({
    client_id: config.clientId,
    redirect_uri: config.redirectUri,
    response_type: "code",
    scope: config.scope,
    state,
    code_challenge: pkce.challenge,
    code_challenge_method: "S256",
    login_hint: did,
  });

  const { json: parJson } = await dpopPost(
    dpopKey,
    meta.pushed_authorization_request_endpoint,
    parBody,
  );
  if (parJson.error) throw new Error("PAR error: " + JSON.stringify(parJson));

  const authUrl = new URL(meta.authorization_endpoint);
  authUrl.searchParams.set("client_id", config.clientId);
  authUrl.searchParams.set("request_uri", parJson.request_uri);
  location.href = authUrl.href;
}

const sw = globalThis;
if (typeof ServiceWorkerGlobalScope !== "undefined" && sw instanceof ServiceWorkerGlobalScope) {
  sw.oninstall = () => sw.skipWaiting();
  sw.onactivate = (e) => e.waitUntil(sw.clients.claim());
  sw.onfetch = async (e) =>
    e.respondWith(
      new Promise(async (resolve) => {
        const url = new URL(e.request.url);
        const code = url.searchParams.get("code");
        const state = url.searchParams.get("state");
        if (code && state) {
          const authing = await getAuthing(state);
          if (authing) return resolve(callback(authing, code, state));
        }

        resolve(authedFetch(e.request));
      }),
    );
}

/**
 * @param {AuthingSession} authing
 * @param {string} code
 * @param {string} state
 */
async function callback(authing, code, state) {
  const body = new URLSearchParams({
    grant_type: "authorization_code",
    code,
    redirect_uri: authing.config.redirectUri,
    client_id: authing.config.clientId,
    code_verifier: authing.verifier,
  });

  const { json: tokenJson, dpopNonce } = await dpopPost(
    authing.dpopKey,
    authing.tokenEndpoint,
    body,
  );
  if (tokenJson.error) {
    return new Response("token error: " + JSON.stringify(tokenJson), { status: 400 });
  }

  /** @type {OAuthSession} */
  const session = {
    pds: authing.pds,
    did: authing.did,
    access_token: tokenJson.access_token,
    token_type: tokenJson.token_type,
    refresh_token: tokenJson.refresh_token,
    dpopKey: authing.dpopKey,
    dpopNonce,
    tokenEndpoint: authing.tokenEndpoint,
    clientId: authing.config.clientId,
    expiresAt: Date.now() + (tokenJson.expires_in ?? 3600) * 1000,
  };
  await putSession(session);
  await deleteAuthing(state);

  // strip the query params and send the browser back to the redirect_uri
  const dest = new URL(authing.config.redirectUri);
  return Response.redirect(dest.href, 302);
}

/** @param {OAuthSession} session */
async function refresh(session) {
  if (!session.refresh_token) throw new Error("No refresh_token in session");

  const body = new URLSearchParams({
    grant_type: "refresh_token",
    refresh_token: session.refresh_token,
    client_id: session.clientId,
  });

  const { json, dpopNonce } = await dpopPost(
    session.dpopKey,
    session.tokenEndpoint,
    body,
    session.dpopNonce,
  );

  if (json.error) throw new Error("Refresh error: " + JSON.stringify(json));
  session.access_token = json.access_token;
  session.expiresAt = Date.now() + (json.expires_in ?? 3600) * 1000;
  if (json.refresh_token) session.refresh_token = json.refresh_token;
  session.dpopNonce = dpopNonce;
}

/**
 * Intercept requests to any PDS we have a session for, adding DPoP and
 * Authorization headers. Pass through everything else unchanged.
 * @param {Request} req
 */
async function authedFetch(req) {
  const url = new URL(req.url);
  const did = req.headers.get("x-atsw-did");

  /** @type {OAuthSession | undefined} */
  let session;
  if (did) session = await getSession(did);
  else {
    const sessions = await getSessionsByPDS(url.origin);
    if (sessions.length > 1)
      throw new Error(`Multiple sessions for ${url.origin}; set x-atsw-did header`);
    session = sessions[0];
  }

  if (!session) return fetch(req);

  if (session.expiresAt <= Date.now() && session.refresh_token) {
    await refresh(session);
    await putSession(session);
  }

  const htu = url.origin + url.pathname;
  const htm = req.method;
  const ath = b64url(await crypto.subtle.digest("SHA-256", enc.encode(session.access_token)));

  let res = new Response();
  for (let attempt = 0; attempt < MAX_DPOP_RETRIES; attempt++) {
    const dpop = await createDPoP(session.dpopKey, htm, htu, session.dpopNonce, ath);

    const headers = new Headers(req.headers);
    headers.delete("x-atsw-did");
    headers.set("authorization", `DPoP ${session.access_token}`);
    headers.set("dpop", dpop);

    res = await fetch(new Request(req.clone(), { headers }));
    const nonce = res.headers.get("dpop-nonce");
    if (nonce) {
      session.dpopNonce = nonce;
      await putSession(session);
    }

    if (res.status !== 401 || !session.dpopNonce) break;
  }

  return res;
}
