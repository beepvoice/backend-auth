# backend-auth

Beep backend auth proxy. At long last, something done properly in Rust. My ancestors are smiling at me, Imperial, can you say the same?

Is basically tailored just for traefik's Forward Authentication system. It takes a `GET`, `POST`, `PUT`, `PATCH` or `DELETE` request, reads a Bearer Auth JWT token if available. Alternatively, the token can be supplied in the querystring as `token`. Tokens in the Authorization header override tokens in the querystring. If it is not available or invalid, request fails with 4XX and traefik rejects the request. Otherwise, a success response is returned with a `X-User-Claim` header containing serialised user information. `OPTIONS` requests are allowed to pass through wholesale.

## Contents of `X-User-Claim`

```json
{
  "userid": "<userid>",
  "clientid": "<clientid>"
}
```

## Errors

`auth` responses with `400` if there is no token supplied, or `401` if there is an error processing the token.
