//! Test-only instrumentation for the database layer.
//!
//! [`QueryCounter`] answers "how many queries did that cost?" exactly,
//! which is the only way to pin down the round-trip budget of a request
//! path in a test. Postgres has no per-session statement counter, and
//! `pg_stat_*` counters are asynchronous and shared across every
//! connection, so the measurement is taken where it is unambiguous: on
//! the wire, in a relay the test puts between sqlx and Postgres.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// A TCP relay in front of Postgres that counts the queries crossing it.
///
/// Connect through [`QueryCounter::url`] instead of the real database URL
/// and every query any pool on that URL executes is counted, whichever
/// connection it went out on. Counting happens at the protocol level —
/// one per `Query` (simple protocol) and one per `Execute` (extended
/// protocol) message — so it matches "queries the server ran", not
/// "`Db` methods called".
pub struct QueryCounter {
    url: String,
    queries: Arc<AtomicU64>,
}

impl QueryCounter {
    /// Starts a relay in front of the database `database_url` points at.
    pub async fn spawn(database_url: &str) -> anyhow::Result<Self> {
        let (prefix, host_port, suffix) = split_authority(database_url)?;
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let local = listener.local_addr()?;
        let queries = Arc::new(AtomicU64::new(0));

        let counted = queries.clone();
        let upstream = host_port.to_string();
        tokio::spawn(async move {
            while let Ok((client, _)) = listener.accept().await {
                let upstream = upstream.clone();
                let counted = counted.clone();
                tokio::spawn(async move {
                    let _ = relay(client, upstream, counted).await;
                });
            }
        });

        // The relay reads the connection's frontend messages itself, so it
        // has to be the plaintext protocol — TLS would make the stream
        // opaque to it.
        let mut url = format!("{prefix}{local}{suffix}");
        url.push(if url.contains('?') { '&' } else { '?' });
        url.push_str("sslmode=disable");
        Ok(Self { url, queries })
    }

    /// The URL to connect through to be counted.
    pub fn url(&self) -> &str {
        &self.url
    }

    /// Queries counted since the last [`QueryCounter::take`], resetting
    /// the counter. Take once after warming a pool to discard sqlx's own
    /// connection setup, then again around the code under test.
    pub fn take(&self) -> u64 {
        self.queries.swap(0, Ordering::Relaxed)
    }
}

/// Splits `postgres://user:pass@host:5432/db?opts` into the part before
/// the host, the `host:port`, and the part after it, so the host can be
/// swapped for the relay's while everything else is preserved verbatim.
fn split_authority(url: &str) -> anyhow::Result<(&str, &str, &str)> {
    let scheme_end = url
        .find("://")
        .ok_or_else(|| anyhow::anyhow!("database url has no scheme: {url}"))?
        + 3;
    let rest = &url[scheme_end..];
    let authority_end = rest.find(['/', '?']).unwrap_or(rest.len());
    let authority = &rest[..authority_end];
    let host_start = authority.rfind('@').map(|i| i + 1).unwrap_or(0);
    Ok((
        &url[..scheme_end + host_start],
        &authority[host_start..],
        &rest[authority_end..],
    ))
}

async fn relay(client: TcpStream, upstream: String, counted: Arc<AtomicU64>) -> anyhow::Result<()> {
    let server = TcpStream::connect(&upstream).await?;
    let (mut client_read, mut client_write) = client.into_split();
    let (mut server_read, mut server_write) = server.into_split();

    let backend = tokio::spawn(async move {
        let _ = tokio::io::copy(&mut server_read, &mut client_write).await;
    });
    let result = count_frontend(&mut client_read, &mut server_write, &counted).await;
    // The frontend half ending means the client hung up; every response it
    // was owed has already been relayed by then.
    backend.abort();
    result
}

/// Relays the client-to-server half of one connection, counting queries.
///
/// The startup packet is the one message with no type byte, so it is read
/// on its own before the loop can assume the regular framing.
async fn count_frontend<R, W>(
    reader: &mut R,
    writer: &mut W,
    counted: &AtomicU64,
) -> anyhow::Result<()>
where
    R: AsyncReadExt + Unpin,
    W: AsyncWriteExt + Unpin,
{
    const SSL_REQUEST: u32 = 80877103;

    let mut length = [0u8; 4];
    if reader.read_exact(&mut length).await.is_err() {
        return Ok(());
    }
    let mut body = vec![0u8; (u32::from_be_bytes(length) as usize).saturating_sub(4)];
    reader.read_exact(&mut body).await?;
    if body.len() == 4 && u32::from_be_bytes([body[0], body[1], body[2], body[3]]) == SSL_REQUEST {
        anyhow::bail!("connect through QueryCounter::url(), which asks for a plaintext connection");
    }
    writer.write_all(&length).await?;
    writer.write_all(&body).await?;
    writer.flush().await?;

    loop {
        let mut header = [0u8; 5];
        if reader.read_exact(&mut header).await.is_err() {
            return Ok(());
        }
        let length = u32::from_be_bytes([header[1], header[2], header[3], header[4]]) as usize;
        let mut body = vec![0u8; length.saturating_sub(4)];
        if !body.is_empty() {
            reader.read_exact(&mut body).await?;
        }
        if matches!(header[0], b'Q' | b'E') {
            counted.fetch_add(1, Ordering::Relaxed);
        }
        writer.write_all(&header).await?;
        writer.write_all(&body).await?;
        writer.flush().await?;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_authority_is_swapped_without_disturbing_the_rest_of_the_url() {
        let (prefix, host, suffix) =
            split_authority("postgres://silo:silo@db.internal:5432/silo?application_name=x")
                .unwrap();
        assert_eq!(prefix, "postgres://silo:silo@");
        assert_eq!(host, "db.internal:5432");
        assert_eq!(suffix, "/silo?application_name=x");
    }

    #[test]
    fn an_authority_with_no_credentials_or_path_still_splits() {
        let (prefix, host, suffix) = split_authority("postgres://localhost").unwrap();
        assert_eq!(prefix, "postgres://");
        assert_eq!(host, "localhost");
        assert_eq!(suffix, "");
    }
}
