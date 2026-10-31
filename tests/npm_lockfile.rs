//! Pins the npm lockfile contract that `docs/operations.md` describes only
//! in prose.
//!
//! A `package-lock.json` records, per package, the exact URL `npm ci` will
//! fetch that package's tarball from: the `resolved` field. The proxy gates
//! an install only if that URL points at the proxy's `public_url`, because
//! the proxy cannot intercept a request that is never sent to it.
//!
//! So there are two facts worth testing, and this file tests both, so a
//! future change to URL construction cannot quietly break either direction:
//!
//! 1. The `dist.tarball` the proxy forwards is exactly
//!    `{public_url}/{tarball_path(name, version)}`. That string is what a
//!    lockfile generated behind the proxy writes into `resolved`. If the
//!    proxy ever changed the shape, every lockfile regenerated against it
//!    would still work while the recorded URL drifted from what the proxy
//!    actually serves.
//! 2. A lockfile generated without the proxy names hosts the proxy does not
//!    serve. This is the defect itself: it routes every install around the
//!    gate. Asserting it here turns "no gate applies" into an executable
//!    statement instead of a paragraph someone has to remember.
//!
//! Everything here is deterministic and hermetic. The lockfile fixtures are
//! inline constants, no registry is contacted, and the `npm` binary is never
//! run. The packument path goes through [`filter_packument`], the same pure
//! function the real cascade calls, rather than through HTTP: the lockfile
//! contract is about URL shape, not about transport.

use serde_json::Value;
use url::Url;

use supply_chain_scanner::ecosystem::npm::packument::{filter_packument, parse_packument};
use supply_chain_scanner::ecosystem::npm::tarball_path;

/// The public registry a lockfile names when it was generated without the
/// proxy. This is the host an `npm ci` would fetch from directly.
const PUBLIC_REGISTRY: &str = "https://registry.npmjs.org";

/// The host this proxy serves. A lockfile generated behind the proxy names
/// only this host.
const PROXY_PUBLIC_URL: &str = "http://proxy.internal.example:8080";

/// One unscoped and one scoped package, the two shapes `tarball_path` has to
/// get right. A scoped name contains a `/`, which is exactly where a naive
/// path join goes wrong.
const PACKAGES: &[(&str, &str)] = &[("lodash", "4.17.21"), ("@babel/core", "7.24.0")];

/// A `lockfileVersion` 3 lockfile as `npm install` would write it with the
/// default public registry, before the org adopted the proxy.
///
/// Minimal but structurally real: a root `""` entry, one entry per package
/// under `packages`, and both `resolved` and `integrity` on every package
/// entry, which is what makes `npm ci` skip resolution entirely and fetch
/// the pinned URL.
const PUBLIC_LOCKFILE: &str = r#"{
  "name": "example-app",
  "version": "1.0.0",
  "lockfileVersion": 3,
  "requires": true,
  "packages": {
    "": {
      "name": "example-app",
      "version": "1.0.0",
      "dependencies": {
        "@babel/core": "^7.24.0",
        "lodash": "^4.17.21"
      }
    },
    "node_modules/@babel/core": {
      "version": "7.24.0",
      "resolved": "https://registry.npmjs.org/@babel/core/-/core-7.24.0.tgz",
      "integrity": "sha512-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=="
    },
    "node_modules/lodash": {
      "version": "4.17.21",
      "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz",
      "integrity": "sha512-BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=="
    }
  }
}"#;

/// The same lockfile as it would look after `npm install` ran with the
/// registry pointed at the proxy. Only the `resolved` base changes; npm
/// leaves the path shape alone, which is why the proxy's forwarded URL has
/// to be a plain `{public_url}/{tarball_path}` concatenation.
fn proxy_lockfile() -> String {
    PUBLIC_LOCKFILE.replace(PUBLIC_REGISTRY, PROXY_PUBLIC_URL)
}

/// Every non-root package name and its `resolved` URL, in lockfile order.
fn package_entries(lockfile: &str) -> Vec<(String, String)> {
    let doc: Value = serde_json::from_str(lockfile).expect("lockfile fixture is valid JSON");
    assert_eq!(
        doc["lockfileVersion"], 3,
        "the fixtures pin lockfileVersion 3; npm writes 2 or 3 for modern installs"
    );
    let packages = doc["packages"]
        .as_object()
        .expect("lockfile fixture has a packages object");
    packages
        .iter()
        .filter(|(key, _)| !key.is_empty())
        .map(|(key, entry)| {
            (
                key.clone(),
                entry["resolved"]
                    .as_str()
                    .unwrap_or_else(|| panic!("package entry {key} has no resolved url"))
                    .to_string(),
            )
        })
        .collect()
}

/// Builds the upstream packument body the proxy would fetch for one package,
/// with `dist.tarball` still pointing at the public registry, as upstream
/// sends it.
fn upstream_packument(name: &str, version: &str) -> String {
    format!(
        r#"{{"name":"{name}","versions":{{"{version}":{{"version":"{version}","dist":{{"tarball":"{PUBLIC_REGISTRY}/{path}","shasum":"0000000000000000000000000000000000000000"}}}}}},"dist-tags":{{"latest":"{version}"}},"time":{{}}}}"#,
        path = tarball_path(name, version),
    )
}

/// The forwarded `dist.tarball` after the real cascade path filters the
/// packument. This is the string npm records as `resolved`.
fn forwarded_tarball(name: &str, version: &str, public_base: &str) -> String {
    let source = parse_packument(&upstream_packument(name, version)).expect("parse packument");
    let keep = vec![version.to_string()];
    let filtered = filter_packument(&source, &keep, public_base);
    filtered["versions"][version]["dist"]["tarball"]
        .as_str()
        .unwrap_or_else(|| panic!("forwarded packument for {name}@{version} has no dist.tarball"))
        .to_string()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// The load-bearing fact. A lockfile generated behind the proxy records
/// whatever `dist.tarball` the proxy forwarded, so that string must be
/// exactly `{public_url}/{tarball_path(name, version)}` for both package
/// shapes. If this drifts, lockfiles written against the proxy stop matching
/// what the proxy actually serves.
#[test]
fn forwarded_tarball_is_exactly_the_url_a_lockfile_records_as_resolved() {
    for (name, version) in PACKAGES {
        let expected = format!("{PROXY_PUBLIC_URL}/{}", tarball_path(name, version));
        let actual = forwarded_tarball(name, version, PROXY_PUBLIC_URL);
        assert_eq!(
            actual, expected,
            "a lockfile generated behind the proxy records the forwarded tarball \
             as resolved, so {name}@{version} must forward exactly \
             {{public_url}}/{{tarball_path}} or every regenerated lockfile \
             pins a URL the proxy does not serve"
        );
    }
}

/// The scoped case spelled out, so a regression names the consequence
/// directly rather than only appearing as an inequality. The `/` in
/// `@babel/core` must stay a real path separator with the `@scope/` prefix
/// retained, while the filename drops the scope.
#[test]
fn scoped_tarball_path_keeps_the_scope_prefix_and_drops_it_from_the_filename() {
    let actual = forwarded_tarball("@babel/core", "7.24.0", PROXY_PUBLIC_URL);
    assert_eq!(
        actual, "http://proxy.internal.example:8080/@babel/core/-/core-7.24.0.tgz",
        "a scoped package's forwarded tarball must be \
         {{public_url}}/@scope/name/-/name-version.tgz; the lockfile records \
         this string verbatim and npm fetches it as written"
    );
}

/// The defect, in executable form. A lockfile generated without the proxy
/// pins `resolved` at the public registry, so `npm ci` fetches those
/// tarballs directly and no gate applies. No host in such a lockfile is the
/// proxy's host, which is precisely why the proxy cannot help.
#[test]
fn a_lockfile_generated_without_the_proxy_names_no_host_the_proxy_serves() {
    let proxy = Url::parse(PROXY_PUBLIC_URL).expect("proxy public_url is a valid url");
    let entries = package_entries(PUBLIC_LOCKFILE);
    assert_eq!(
        entries.len(),
        PACKAGES.len(),
        "the fixture must cover every package shape this file tests"
    );

    for (key, resolved) in &entries {
        let url = Url::parse(resolved).unwrap_or_else(|e| panic!("{key} resolved {resolved}: {e}"));
        assert_ne!(
            url.host_str(),
            proxy.host_str(),
            "lockfile entry {key} resolves to {resolved}, which is the proxy's own \
             host; this test exists to pin the opposite: a lockfile made before \
             the proxy names only foreign hosts"
        );
        assert_eq!(
            url.host_str(),
            Url::parse(PUBLIC_REGISTRY)
                .expect("public registry url")
                .host_str(),
            "lockfile entry {key} resolves to {resolved}; a pre-proxy lockfile \
             pins the public registry, so npm ci fetches it directly and the \
             gate never sees the request"
        );
    }
}

/// The converse direction, and the one the proxy can enforce. A lockfile
/// generated behind the proxy names only the proxy, and the path component
/// it recorded is byte-for-byte the `tarball_path` the proxy builds. Asserting
/// both halves pins that the two directions agree: regenerating a lockfile
/// behind the proxy is sufficient to route every install through the gate,
/// and nothing else about the URL changes.
#[test]
fn a_lockfile_generated_behind_the_proxy_names_only_the_proxy() {
    let lockfile = proxy_lockfile();
    let entries = package_entries(&lockfile);
    assert_eq!(
        entries.len(),
        PACKAGES.len(),
        "the rewritten fixture must still cover every package shape"
    );

    for (key, resolved) in &entries {
        assert!(
            resolved.starts_with(&format!("{PROXY_PUBLIC_URL}/")),
            "lockfile entry {key} resolves to {resolved}, which does not start with \
             the proxy's public_url; such an install would bypass the gate"
        );
        assert!(
            !resolved.contains(PUBLIC_REGISTRY),
            "lockfile entry {key} still names the public registry at {resolved}; \
             a lockfile generated behind the proxy must not leak the upstream"
        );

        let path = resolved
            .strip_prefix(&format!("{PROXY_PUBLIC_URL}/"))
            .expect("prefix checked above");
        let (name, version) = PACKAGES
            .iter()
            .find(|(name, version)| {
                path == tarball_path(name, version)
                    && key.ends_with(&format!("node_modules/{name}"))
            })
            .unwrap_or_else(|| panic!("no fixture package matches lockfile entry {key}"));
        assert_eq!(
            path,
            tarball_path(name, version),
            "the path a behind-the-proxy lockfile records for {name}@{version} must \
             equal tarball_path's {name}/-/<unscoped>-{version}.tgz shape; if the \
             two disagree the proxy forwards a url the lockfile cannot reuse"
        );
    }
}
