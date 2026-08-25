use tonic::{Request, Status};

/// Checks the `authorization: Bearer <token>` gRPC metadata against the
/// expected token. Used as a per-call gate inside each handler rather than
/// a blanket interceptor, since Publish and Read use different tokens.
#[allow(clippy::result_large_err)] // Status is tonic's standard error type; boxing it here would just push the cost to every caller
pub fn check_bearer(req: &Request<impl Sized>, expected: &str) -> Result<(), Status> {
    let header = req
        .metadata()
        .get("authorization")
        .ok_or_else(|| Status::unauthenticated("missing authorization header"))?;
    let value = header
        .to_str()
        .map_err(|_| Status::unauthenticated("invalid authorization header"))?;
    let token = value
        .strip_prefix("Bearer ")
        .ok_or_else(|| Status::unauthenticated("expected Bearer token"))?;

    if token == expected {
        Ok(())
    } else {
        Err(Status::unauthenticated("invalid token"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req_with_auth(value: Option<&str>) -> Request<()> {
        let mut req = Request::new(());
        if let Some(v) = value {
            req.metadata_mut()
                .insert("authorization", v.parse().unwrap());
        }
        req
    }

    #[test]
    fn accepts_matching_bearer_token() {
        let req = req_with_auth(Some("Bearer secret"));
        assert!(check_bearer(&req, "secret").is_ok());
    }

    #[test]
    fn rejects_mismatched_token() {
        let req = req_with_auth(Some("Bearer wrong"));
        assert!(check_bearer(&req, "secret").is_err());
    }

    #[test]
    fn rejects_missing_header() {
        let req = req_with_auth(None);
        assert!(check_bearer(&req, "secret").is_err());
    }

    #[test]
    fn rejects_non_bearer_scheme() {
        let req = req_with_auth(Some("Basic secret"));
        assert!(check_bearer(&req, "secret").is_err());
    }
}
