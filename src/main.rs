extern crate iron;
extern crate router;
extern crate rustc_serialize;
extern crate crypto;
#[macro_use] extern crate hyper;


use iron::{Iron, Request, Response, IronResult};
use iron::status;
use router::Router;
use rustc_serialize::json;
use rustc_serialize::hex::ToHex;
use std::io;
use std::io::Read;
use std::process::Command;

use crypto::digest::Digest;
use crypto::sha1::Sha1;
use crypto::hmac::Hmac;
use crypto::mac::Mac;

header! { (XHubSignature, "X-Hub-Signature") => [String] }
header! { (XGithubEvent, "X-GitHub-Event") => [String] }

#[derive(RustcDecodable)]
struct GithubPullRequest {
    diff_url: String
}

#[derive(RustcDecodable)]
struct GithubPayload {
    pull_request: GithubPullRequest
}

#[derive(RustcEncodable)]
struct GithubResponse {
    msg: String
}

fn check_status(url: String) -> bool {
    let cmd = format!("!(curl -fssL {} | grep -E \"^\\+\" | grep -E \"\\s+$\" &> /dev/null)", url);
    return match Command::new("/bin/sh").arg("-c").arg(cmd).output() {
        Ok(ok) => ok.status.success(),
        Err(_) => false
    };
}

fn check_signature(payload : String, sig: String, token : &str) -> bool {

    let mut hmac = Hmac::new(Sha1::new(), token.as_bytes());
    hmac.input(&payload.as_bytes()[..]);

    println!("{}\n{}", sig.replace("sha1=", ""), hmac.result().code().to_hex());
    println!("{}\n", token);

    sig.replace("sha1=", "") == hmac.result().code().to_hex()
}

fn payload(req: &mut Request, token : &str) -> IronResult<Response> {

    let signature : String = match req.headers.get::<XHubSignature>() {
        Some(hdr) => hdr.to_string(),
        None => return Ok(Response::with((status::BadRequest, "No signature!")))
    };

    let event : String = match req.headers.get::<XGithubEvent>() {
        Some(hdr) => hdr.to_string(),
        None => return Ok(Response::with((status::BadRequest, "No event!")))
    };

    if event != "pull_request" {
        return Ok(Response::with((status::NotImplemented, "We support only pull_request")));
    }

    let mut payload = String::new();
    if req.body.read_to_string(&mut payload).is_err() {
        return Ok(Response::with((status::BadRequest, "Request is not valid UTF-8!")));
    };

    if ! check_signature(payload.clone(), signature, token) {
        return Ok(Response::with((status::Unauthorized, "Bad signature!")));
    }

    let gh_payload : GithubPayload = match json::decode(&payload) {
        Ok(ok) => ok,
        Err(err) => return Ok(Response::with((status::BadRequest, format!("{}", err))))
    };

    let status = check_status(gh_payload.pull_request.diff_url);

    let greeting = GithubResponse { msg: format!("{}", status) };
    let payload = match json::encode(&greeting) {
        Ok(ok) => ok,
        Err(_) => return Ok(Response::with((status::InternalServerError, "Error code: 1")))
    };

    Ok(Response::with((status::Ok, payload)))
}

fn main() {
    //let host = "127.0.0.1:8080";

    println!("Adress to listen (eg. 127.0.0.1:8080):");
    let mut host = String::new();
    io::stdin().read_line(&mut host).expect("Failed to read line");

    println!("Secret token:");
    let mut token = String::new();
    io::stdin().read_line(&mut token).expect("Failed to read line");

    let mut router = Router::new();
    router.post("/payload", move |r : &mut Request| payload(r, token.trim()));

    match Iron::new(router).http(host.trim()) {
        Ok(ok) => println!("webhook url: http://{}/payload", ok.socket),
        Err(err) => println!("[ERROR] Cannot create server: {:?}", err)
    };
}
