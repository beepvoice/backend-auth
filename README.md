# backend-auth

Beep backend auth proxy. At long last, something done properly in Rust. My ancestors are smiling at me, Imperial, can you say the same?

Is basically tailored just for traefik's Forward Authentication system. It takes a `GET`, `POST`, `PUT`, `PATCH` or `DELETE` request, reads a Bearer Auth JWT token if available. If it is not available or invalid, request fails with 4XX and traefik rejects the request. Otherwise, a success response is returned with a `X-User-Claim` header containing serialised user information. `OPTIONS` requests are allowed to pass through wholesale.

## Contents of `X-User-Claim`

```json
{
  "userid": "<userid>",
  "clientid": "<clientid>"
}
```
