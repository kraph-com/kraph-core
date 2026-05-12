//! Runtime interop check between the TS gateway minter and the Rust
//! verifier. Run as:
//!
//!   SECRET=phase3-secret cargo run --example verify_studio_token -- <token>
//!
//! Prints OK + the decoded claims if the HMAC + payload match, exits
//! non-zero with the error otherwise.

fn main() {
    let secret = std::env::var("SECRET").expect("SECRET env required");
    let token = std::env::args()
        .nth(1)
        .expect("usage: verify_studio_token <token>");

    // We import the binary's modules by including them as a path. The
    // example crate type doesn't get the bin's modules for free, so we
    // re-include just the studio_proxy module verbatim.
    #[path = "../src/studio_proxy.rs"]
    mod studio_proxy;

    match studio_proxy::verify_token(&secret, &token) {
        Ok(c) => {
            println!("OK  w={} i={} exp={}", c.w, c.i, c.e);
        }
        Err(e) => {
            eprintln!("FAIL: {}", e);
            std::process::exit(1);
        }
    }
}
