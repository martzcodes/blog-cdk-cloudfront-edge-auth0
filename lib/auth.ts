import type {
  CloudFrontHeaders,
  CloudFrontRequest,
  CloudFrontRequestEvent,
  CloudFrontResponse,
} from "aws-lambda";
import {
  GetSecretValueCommand,
  SecretsManagerClient,
} from "@aws-sdk/client-secrets-manager";
import { request as httpsRequest } from "https";
import { parse, ParsedUrlQuery, stringify } from "querystring";
import { verify } from "jsonwebtoken";
import type { Algorithm } from "jsonwebtoken";
const SecretId = "blog-cloudformation-edge/auth0";

const sm = new SecretsManagerClient({});

const PUBLIC_PATHS = [/\/favicons\//];

const unauthorizedResponse = {
  status: "401",
  statusDescription: "Unauthorized",
  body: `
    <\!DOCTYPE html>
    <html lang="en">
      <head>
        <meta charset="utf-8">
        <title>Unauthorized</title>
      </head>
      <body>
        <p>Unauthorized</p>
      </body>
    </html>
    `,
};

export interface Auth0Creds {
  certificate: string;
  AUTH0_CLIENT_ID: string;
  AUTH0_CLIENT_SECRET: string;
  AUTH0_ALGORITHM: Algorithm;
  AUTH0_DOMAIN: string;
  AUTH0_HOST: string;
  AUTH0_LOGIN_URL: string;
  CALLBACK_PATH: string;
}

let auth0Creds: Auth0Creds;

const redirect = (
  newLocation: string,
  cookies: { name: string; value: string }[]
): CloudFrontResponse => {
  const result: CloudFrontResponse = {
    status: "302",
    statusDescription: "Found",
    headers: {
      location: [
        {
          key: "Location",
          value: newLocation,
        },
      ],
    },
  };

  if (cookies) {
    result.headers["set-cookie"] = cookies.map((c) => ({
      key: "set-cookie",
      value: `${c.name}=${c.value}`,
    }));
  }

  return result;
};

const loginCallback = async (
  request: CloudFrontRequest
): Promise<CloudFrontResponse | void> => {
  console.log(
    `callback? ${request.uri} !== ${auth0Creds.CALLBACK_PATH}: ${
      request.uri !== auth0Creds.CALLBACK_PATH
    }`
  );
  if (request.uri !== auth0Creds.CALLBACK_PATH) {
    return;
  }

  let params: ParsedUrlQuery;
  try {
    params = parse(request.querystring);
    if (params.error) {
      console.log(params.error);
      throw new Error("Unauthorized");
    }
    if (!params.code) {
      return;
    }
  } catch (err) {
    console.log(err);
    return;
  }

  // Call Auth0 to get JWT token
  const postData = stringify({
    client_id: auth0Creds.AUTH0_CLIENT_ID,
    redirect_uri: `https://${request.headers.host[0].value}${auth0Creds.CALLBACK_PATH}`,
    client_secret: auth0Creds.AUTH0_CLIENT_SECRET,
    code: params.code,
    grant_type: "authorization_code",
  });
  const postOptions = {
    host: auth0Creds.AUTH0_DOMAIN,
    port: 443,
    path: "/oauth/token",
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
      "Content-Length": postData.length,
    },
  };
  const tokenRequest: Promise<CloudFrontResponse> = new Promise((resolve) => {
    const req = httpsRequest(postOptions, (res) => {
      if (!res) {
        throw new Error("No Res");
      }
      if (res.statusCode! >= 300) {
        throw new Error("Bad Response");
      }

      let body = "";
      res.on("data", (d) => (body += d));
      res.on("end", () => {
        const json = JSON.parse(body);
        const token = json.id_token;

        if (!token) {
          throw new Error("Unauthorized");
        }

        // store this in a cookie, then redirect the user
        const dest = `https://${request.headers.host[0].value}${
          params.dest || "/"
        }`;
        return resolve(
          redirect(dest, [{ name: "session-token", value: token }])
        );
      });
    });
    req.on("error", (e) => {
      throw e;
    });
    req.write(postData);
    req.end();
  });
  return tokenRequest;
};

const parseCookies = (headers: CloudFrontHeaders) => {
  const parsedCookie: Record<string, string> = {};
  if (headers.cookie) {
    headers.cookie[0].value.split(";").forEach((cookie) => {
      if (cookie) {
        const parts = cookie.split("=");
        parsedCookie[parts[0].trim()] = parts[1].trim();
      }
    });
  }
  return parsedCookie;
};

const validateToken = (token: string) => {
  try {
    verify(token, auth0Creds.certificate, {
      algorithms: [auth0Creds.AUTH0_ALGORITHM],
      audience: auth0Creds.AUTH0_CLIENT_ID,
    });
  } catch (e) {
    return false;
  }
  return true;
};

const validateCookie = (cookie: string) => {
  return !!cookie && validateToken(cookie);
};

const checkToken = (request: CloudFrontRequest) => {
  const headers = request.headers;

  /* Check for session-id in request cookie in viewer-request event,
   * if session-id is absent, redirect the user to sign in page with original
   * request sent as redirect_url in query params.
   */

  /* Check for session-id in cookie, if present then proceed with request */
  const parsedCookies = parseCookies(headers);
  if (validateCookie(parsedCookies["session-token"])) {
    return; // not handled
  }

  // User is not authenticated.
  /* URI encode the original request so we can send as query param for when user is finally logged in */
  const encodedRedirectUrl = encodeURIComponent(
    request.querystring ? `${request.uri}?${request.querystring}` : request.uri
  );
  const callbackUrl = `https://${request.headers.host[0].value}${auth0Creds.CALLBACK_PATH}?dest=${encodedRedirectUrl}`;
  const encodedCallback = encodeURIComponent(callbackUrl);
  const redirectUrl = `${auth0Creds.AUTH0_LOGIN_URL}?client=${auth0Creds.AUTH0_CLIENT_ID}&redirect_uri=${encodedCallback}`;

  return redirect(redirectUrl, [{ name: "session-token", value: "" }]);
};

export const handler = async (event: CloudFrontRequestEvent) => {
  const request = event.Records[0].cf.request;

  if (PUBLIC_PATHS.find((pattern) => pattern.test(request.uri))) {
    return request;
  }

  try {
    if (!auth0Creds) {
      const getSecret = new GetSecretValueCommand({
        SecretId,
      });
      const secret = await sm.send(getSecret);
      auth0Creds = JSON.parse(secret.SecretString!) as Auth0Creds;
    }
    const loggedIn = await loginCallback(request);
    if (loggedIn) {
      console.log("was login callback");
      return loggedIn;
    }
    const redirectToLogin = checkToken(request);
    if (redirectToLogin) {
      console.log("not logged in");
      return redirectToLogin;
    }

    console.log("authenticated!");
    return request;
  } catch (e) {
    console.log(e);
    return unauthorizedResponse;
  }
};
