#[macro_use]
extern crate serde;
extern crate serde_json;
#[macro_use]
extern crate lazy_static;
extern crate dotenv;
extern crate iron;
extern crate router;
extern crate jsonwebtoken as jwt;
extern crate urlencoded;

use dotenv::dotenv;
use iron::prelude::*;
use iron::headers::{ Authorization, Bearer };
use iron::status::Status;
use router::Router;
use urlencoded::{ UrlDecodingError, UrlEncodedQuery };
use std::env;

#[derive(Debug, Serialize, Deserialize)]
struct UserClaims {
    userid: String,
    clientid: String,
}

fn main() {
    dotenv().ok();

    let listen = env::var("LISTEN").unwrap();

    lazy_static! {
        static ref secret:String = env::var("SECRET").unwrap();
    }

    fn verify_jwt(req:&mut Request) -> IronResult<Response> {
        let mut token = None;

        // Check token from querystring
        match req.get_ref::<UrlEncodedQuery>() {
            Ok(ref hashmap) => {
                if let Some(token_vec) = hashmap.get("token") {
                    if !token_vec.is_empty() {
                        token = Some(token_vec[0].clone());
                    }
                }
            },
            Err(UrlDecodingError::BodyError(_)) => return Ok(Response::with((Status::BadRequest, "400 Bad Request"))),
            Err(UrlDecodingError::EmptyQuery) => (),
        };

        // Check token from Authorization header
        if let Some(authorisation_header) = req.headers.get::<Authorization<Bearer>>() {
            token = Some(authorisation_header.token.clone());
        }

        // Process token
        if let Some(token) = token {
            match jwt::decode::<UserClaims>(&token, secret.as_ref(), &jwt::Validation{ validate_exp:false, ..Default::default()}) { // Don't validate expiry
            // match jwt::decode::<UserClaims>(&authorisation_header.token, secret.as_ref(), &jwt::Validation::default()) { // Production version
                Ok(decoded) => {
                    let user_string = match serde_json::to_string(&decoded.claims) {
                        Ok(s) => s,
                        Err(_) => return Ok(Response::with((Status::Unauthorized, "401 Unauthorised"))),
                    };
                    let mut res = Response::with((Status::Ok, "200 Ok"));
                    res.headers.set_raw("X-User-Claim", vec![user_string.as_bytes().to_vec()]);
                    Ok(res)
                },
                Err(_) => Ok(Response::with((Status::Unauthorized, "401 Unauthorised")))
            }
        } else {
            Ok(Response::with((Status::BadRequest, "400 Bad Request")))
        }
    }

    let mut router = Router::new();
    // Let OPTIONS through
    router.options("/auth", success, "auth_options");
    // Auth GET, POST, PUT, PATCH, DELETE
    router.get("/auth", verify_jwt, "auth_get");
    router.post("/auth", verify_jwt, "auth_post");
    router.put("/auth", verify_jwt, "auth_put");
    router.patch("/auth", verify_jwt, "auth_patch");
    router.delete("/auth", verify_jwt, "auth_delete");

    match Iron::new(router).http(&listen) {
        Ok(_) => println!("Listening on {}", &listen),
        Err(e) => println!("Error: {:?}", e),
    };
}

fn success(_:&mut Request) -> IronResult<Response> {
    Ok(Response::with((Status::Ok, "")))
}
