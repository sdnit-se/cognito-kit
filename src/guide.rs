//! Walkthroughs, one chapter per job.
//!
//! Read them in this order. If you protect an API, start with access
//! tokens.
//!
//! 1. [Checking access tokens](access_tokens), with custom attributes, the
//!    axum extractor and the tower layer.
//! 2. [Web sign-in with managed login](web_sign_in).
//! 3. [An MCP server behind Cognito](mcp_server).
//! 4. [Letting assistants register themselves](self_registration).
//! 5. [Testing with the test kit](testing).
//! 6. [The OpenTofu module](opentofu).
//! 7. [Production notes](production): key caching, status codes, Lambda,
//!    and the security model.
//!
//! This module holds documentation only. It exists when rustdoc builds or
//! tests the docs, and never in your binary. Each chapter's examples run as
//! doctests with every feature on.

// The chapters use every feature, as docs.rs builds them. A build with fewer
// features gets a pointer instead, so links to the chapters still resolve.
macro_rules! chapter {
    ($name:ident, $file:literal) => {
        #[cfg_attr(
            all(feature = "axum", feature = "tower", feature = "test-kit", feature = "dynamodb"),
            doc = include_str!(concat!("../docs/guide/", $file))
        )]
        #[cfg_attr(
            not(all(feature = "axum", feature = "tower", feature = "test-kit", feature = "dynamodb")),
            doc = "This chapter's examples need every feature. Build it with `cargo doc --all-features`, or read it on docs.rs."
        )]
        pub mod $name {}
    };
}

chapter!(access_tokens, "access-tokens.md");
chapter!(web_sign_in, "web-sign-in.md");
chapter!(mcp_server, "mcp-server.md");
chapter!(self_registration, "self-registration.md");
chapter!(testing, "testing.md");
chapter!(opentofu, "opentofu.md");
chapter!(production, "production.md");
