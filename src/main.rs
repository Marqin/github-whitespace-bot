extern crate iron;
extern crate router;
extern crate rustc_serialize;

use iron::{Iron, Request, Response, IronResult};
use iron::status;
use router::Router;
use rustc_serialize::json;
use std::io::Read;
use std::process::Command;

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

fn payload(req: &mut Request) -> IronResult<Response> {

    let mut payload = String::new();
    if req.body.read_to_string(&mut payload).is_err() {
        return Ok(Response::with((status::BadRequest, "Request is not valid UTF-8!")));
    };

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
    let host = "127.0.0.1:8080";

    let mut router = Router::new();
    router.post("/payload", payload);

    match Iron::new(router).http(host) {
        Ok(ok) => println!("webhook url: http://{}/payload", ok.socket),
        Err(err) => println!("[ERROR] Cannot create server: {:?}", err)
    };
}
