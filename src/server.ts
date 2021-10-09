import {
  AccessTokenResponseOptions,
  Application,
  AuthorizationRequestOptions,
  AuthorizationResponseOptions,
  Context,
  cryptoRandomString,
  dotEnvConfig,
  OAuth2ClientOptions,
  processAccessTokenRequest,
  processAuthorizeRequest,
  processClientAuthentication,
  Router,
  URLAuthorizeResponse,
} from "../deps.ts";

const router = new Router();
const env = dotEnvConfig();

const codeCache: Map<string, AuthorizationRequestOptions> = new Map();
const requestCache: Map<string, AuthorizationRequestOptions> = new Map();

const clients: OAuth2ClientOptions[] = [{
  clientId: env.DENO_CLIENT_ID,
  clientSecret: env.DENO_CLIENT_SECRET,
  clientRedirectURIs: ["http://localhost:3000/callback"],
  scope: "foo bar",
  state: "N/A",
  codeVerifier: "N/A",
  codeChallenge: "N/A",
}];

router.get("/authorize", (ctx: Context) => {
  console.log(`-> GET /authorize`);
  const authorizeRequest = processAuthorizeRequest(ctx, clients);
  if (!authorizeRequest) return;

  // Store parsed request until consent OR TTL expires (@todo TTL)
  const requestIdentifier: string = cryptoRandomString({ length: 12, type: "alphanumeric" });
  requestCache.set(requestIdentifier, authorizeRequest);

  const writeout = `
    <html>
      <body>
        <h1>Authorize this?</h1>
        <form  method="post" action="${ctx.request.url.origin}/approve">
        <input type="hidden" name="reqid" value="${requestIdentifier}">
        <p>${ctx.request.url.search}</p>
        <input type="submit" target="top" value="Sure!"></input>
        </form>
      </body>
    </html>`;

  ctx.response.body = writeout;
});

router.post("/approve", async (ctx) => {
  console.log(`-> POST /approve`);
  if (!ctx.request.hasBody || ctx.request.body().type !== "form") {
    return;
  } else {
    const body = ctx.request.body();
    const params: URLSearchParams = await body.value;
    const requestId = params.get("reqid") || "N/A";

    // Pull original request out of cache
    const orgRequest = requestCache.get(requestId);

    if (orgRequest) {
      const code: string = cryptoRandomString({ length: 12, type: "url-safe" });
      const state = orgRequest.state;
      const responseOptions: AuthorizationResponseOptions = { code: code, state: state };
      const UrlAuthorize = URLAuthorizeResponse(orgRequest.redirectURI, responseOptions);

      codeCache.set(code, orgRequest); // Store decision
      requestCache.delete(requestId); // 🔥 burn cached request

      console.log(`<- Redirect back to client ${UrlAuthorize}`);
      ctx.response.redirect(UrlAuthorize);
    } //@todo invalid requestId
  }
});

router.post("/token", async (ctx) => {
  console.log(`-> POST /token`);
  const clientAuthenticated = await processClientAuthentication(ctx, clients);
  if (!clientAuthenticated || !ctx.request.hasBody) return;

  const requestOptions = await processAccessTokenRequest(ctx, clientAuthenticated, codeCache);
  if (!requestOptions) return;

  requestOptions ? codeCache.delete(requestOptions.code) : {}; // 🔥 burn code

  // Issue token
  const accessToken: AccessTokenResponseOptions = {
    access_token: cryptoRandomString({ length: 24, type: "alphanumeric" }),
    token_type: "Bearer",
    expires_in: 3600,
    refresh_token: cryptoRandomString({ length: 24, type: "alphanumeric" }),
  };
  console.log(`<- Give back token: ${accessToken}`);
  ctx.response.status = 200;
  ctx.response.headers.append("Content-Type", "application/json");
  ctx.response.body = accessToken;
});

const app = new Application();
app.use(async (ctx, next) => {
  await next();
  console.log(`${ctx.request.method} ${ctx.request.url}`);
});

const port = 9001;
app.use(router.routes());
app.use(router.allowedMethods());

console.info(`Authorization server listening on :${port}`);
app.listen({ port: port });
