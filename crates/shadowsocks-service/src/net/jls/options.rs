//! JLS options carried by SIP003 `plugin_opts`, in the form of `key=value;key=value`

use std::{
    io::{self, ErrorKind},
    net::SocketAddr,
};

use shadowsocks::relay::socks5::Address;

/// ALPN offered by the client by default, same as mihomo
const DEFAULT_ALPN: &[&str] = &["h2", "http/1.1"];

/// JLS client options: `host=...;username=...;password=...[;alpn=h2,http/1.1]`
///
/// `username` and `password` are the same as mihomo's `plugin-opts`, which are `user_iv` and `user_pwd` in rustls-jls.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JlsClientOptions {
    /// SNI sent to the server, must match the server's `sni` (or `dest` domain) exactly
    pub host: String,
    pub username: String,
    pub password: String,
    pub alpn: Vec<String>,
}

impl JlsClientOptions {
    pub fn parse(opts: &str) -> io::Result<Self> {
        let (mut host, mut username, mut password, mut alpn) = (None, None, None, None);
        for (key, value) in parse_pairs(opts, &["host", "username", "password", "alpn"])? {
            match key {
                "host" => host = Some(value.to_ascii_lowercase()),
                "username" => username = Some(value.to_owned()),
                "password" => password = Some(value.to_owned()),
                _ => alpn = Some(value.split(',').map(ToOwned::to_owned).collect()),
            }
        }

        Ok(Self {
            host: required("host", host)?,
            username: required("username", username)?,
            password: required("password", password)?,
            alpn: alpn.unwrap_or_else(|| DEFAULT_ALPN.iter().map(|s| (*s).to_owned()).collect()),
        })
    }
}

/// JLS server options: `username=...;password=...;dest=host:port[;sni=...]`
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JlsServerOptions {
    pub username: String,
    pub password: String,
    /// Camouflage website, unauthenticated connections are forwarded to it
    pub dest: Address,
    /// Expected client SNI, defaults to the domain of `dest`
    pub sni: Option<String>,
}

impl JlsServerOptions {
    pub fn parse(opts: &str) -> io::Result<Self> {
        let (mut username, mut password, mut dest, mut sni) = (None, None, None, None);
        for (key, value) in parse_pairs(opts, &["username", "password", "dest", "sni"])? {
            match key {
                "username" => username = Some(value.to_owned()),
                "password" => password = Some(value.to_owned()),
                "dest" => dest = Some(parse_dest(value)?),
                _ => sni = Some(value.to_ascii_lowercase()),
            }
        }

        Ok(Self {
            username: required("username", username)?,
            password: required("password", password)?,
            dest: required("dest", dest)?,
            sni,
        })
    }
}

fn parse_dest(value: &str) -> io::Result<Address> {
    if let Ok(addr) = value.parse::<SocketAddr>() {
        return Ok(Address::SocketAddress(addr));
    }
    match value.rsplit_once(':') {
        Some((host, port)) if !host.is_empty() => match port.parse::<u16>() {
            Ok(port) => Ok(Address::DomainNameAddress(host.to_ascii_lowercase(), port)),
            Err(..) => Err(invalid(format!("jls option `dest` = `{value}` has an invalid port"))),
        },
        _ => Err(invalid(format!(
            "jls option `dest` = `{value}` is not in `host:port` form"
        ))),
    }
}

fn parse_pairs<'a>(opts: &'a str, keys: &[&str]) -> io::Result<Vec<(&'a str, &'a str)>> {
    let mut pairs = Vec::new();
    for item in opts.split(';').filter(|s| !s.is_empty()) {
        let (key, value) = item
            .split_once('=')
            .ok_or_else(|| invalid(format!("jls option `{item}` is not in `key=value` form")))?;
        if !keys.contains(&key) {
            return Err(invalid(format!("unknown jls option `{key}`, expecting {keys:?}")));
        }
        if value.is_empty() {
            return Err(invalid(format!("jls option `{key}` is empty")));
        }
        pairs.push((key, value));
    }
    Ok(pairs)
}

fn required<T>(key: &str, value: Option<T>) -> io::Result<T> {
    value.ok_or_else(|| invalid(format!("missing jls option `{key}`")))
}

fn invalid(msg: String) -> io::Error {
    io::Error::new(ErrorKind::InvalidInput, msg)
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn parse_client_options() {
        let opts = JlsClientOptions::parse("host=WWW.Example.com;username=u;password=p").unwrap();
        assert_eq!(opts.host, "www.example.com");
        assert_eq!(opts.username, "u");
        assert_eq!(opts.password, "p");
        assert_eq!(opts.alpn, ["h2", "http/1.1"]);

        let opts = JlsClientOptions::parse("host=a.com;username=u;password=p=;alpn=http/1.1").unwrap();
        assert_eq!(opts.password, "p=");
        assert_eq!(opts.alpn, ["http/1.1"]);

        assert!(JlsClientOptions::parse("host=a.com;username=u").is_err());
        assert!(JlsClientOptions::parse("host=a.com;username=u;password=").is_err());
        assert!(JlsClientOptions::parse("host=a.com;username=u;password=p;fingerprint=chrome").is_err());
        assert!(JlsClientOptions::parse("host=a.com;username=u;password").is_err());
        assert!(JlsClientOptions::parse("").is_err());
    }

    #[test]
    fn parse_server_options() {
        let opts = JlsServerOptions::parse("username=u;password=p;dest=WWW.example.com:443").unwrap();
        assert_eq!(opts.dest, Address::DomainNameAddress("www.example.com".to_owned(), 443));
        assert_eq!(opts.sni, None);

        let opts = JlsServerOptions::parse("username=u;password=p;dest=127.0.0.1:8443;sni=A.com").unwrap();
        assert_eq!(opts.dest, Address::SocketAddress("127.0.0.1:8443".parse().unwrap()));
        assert_eq!(opts.sni.as_deref(), Some("a.com"));

        assert!(JlsServerOptions::parse("username=u;password=p").is_err());
        assert!(JlsServerOptions::parse("username=u;password=p;dest=www.example.com").is_err());
        assert!(JlsServerOptions::parse("username=u;password=p;dest=a.com:443;host=a.com").is_err());
    }
}
