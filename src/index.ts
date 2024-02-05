import express from 'express';
import session from 'express-session';
import crypto from 'crypto';
import { Issuer, TokenSet, generators } from 'openid-client';

declare module 'express-session' {
  export interface SessionData {
    tokenSet: TokenSet;
    state: string;
    codeVerifier: string;
    nonce: string;
    originalUrl: string;
    isRedirected: boolean;
    isLoggedIn: boolean;
  }
}

const app: express.Express = express()
const PORT = 3000

app.use(session({
  name: 'SESSION',
  secret: [crypto.randomBytes(32).toString('hex')],
  resave: false,
  saveUninitialized: true
}))

/**
 * routes
 */
app.get('/*', async (req: express.Request, res: express.Response) => {
  if (req.session.isLoggedIn && req.session.isRedirected) {
    console.log('received and validated tokens %j', req.session.tokenSet);
    return res.send('OK');
  }
  const redirectUri = 'http://localhost:3000/cb'
  const issuer = await Issuer.discover('https://access.line.me/.well-known/openid-configuration')
  const client = new issuer.Client({
    client_id: process.env.LINE_CLIENT_ID || '<LINE_CLIENT_ID>',
    client_secret: process.env.LINE_CLIENT_SECRET || '<LINE_CLIENT_SECRET>',
    redirect_uris: [redirectUri],
    response_types: ['code'],
    id_token_signed_response_alg: 'HS256'
  })
  if (req.session.isRedirected) {
    const state = req.session.state;
    const nonce = req.session.nonce;
    const codeVerifier = req.session.codeVerifier;
    const params = client.callbackParams(req);
    const tokenSet = await client.callback(
      redirectUri,
      params,
      {
        state,
        nonce,
        code_verifier: codeVerifier
      });
    req.session.tokenSet = tokenSet;
    req.session.isLoggedIn = true;
    return res.redirect(req.session.originalUrl!);
  }
  const state = generators.state();
  req.session.state = state;
  const nonce = generators.nonce();
  req.session.nonce = nonce;

  const codeVerifier = generators.codeVerifier();
  const codeChallenge = generators.codeChallenge(codeVerifier);
  req.session.codeVerifier = codeVerifier;

  const url = client.authorizationUrl({
    scope: 'openid',
    state,
    nonce,
    code_challenge: codeChallenge,
    code_challenge_method: 'S256',
  })
  req.session.originalUrl = req.originalUrl;
  req.session.isRedirected = true;
  return res.redirect(url);
});

app.listen(PORT, () => {
  console.log(`listen port: ${PORT}`);
});