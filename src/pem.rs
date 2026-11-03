//! PEM certificate parsing shared by the TLS backends.

use rustls_pki_types::{
    CertificateDer,
    pem::{PemObject, SectionKind},
};
use std::io;

/// The custom roots of `TLSConfig::cert_chain`, or `InvalidData` if one of its
/// certificates is malformed. A chain without certificates adds no roots.
///
/// `TRUSTED CERTIFICATE` objects are skipped, as OpenSSL's certificate reader
/// skips them: their trust settings can restrict or reject the root.
pub(crate) fn custom_roots(cert_chain: &str) -> io::Result<Vec<CertificateDer<'static>>> {
    pem_certificates(cert_chain.as_bytes())
        .ok_or_else(|| crate::invalid_data("custom certificate chain is malformed"))
}

/// A PEM object's label and encapsulated lines.
type Object<'pem> = (&'pem [u8], Vec<&'pem [u8]>);

/// The label and encapsulated lines of each object in `pem` whose label `select` accepts,
/// or `None` if such an object is malformed or another object starts inside it.
/// With `first_only`, reading stops after the first such object, as the PEM key
/// readers do.
///
/// As in the PEM parsers, lines end at CR or LF, and boundaries start a line;
/// an object can also start right after another one's end boundary. Lines may
/// start with a UTF-8 byte order mark. Text between objects and the contents of
/// unselected objects are skipped.
fn pem_objects(
    pem: &[u8],
    select: impl Fn(&[u8]) -> bool,
    first_only: bool,
) -> Option<Vec<Object<'_>>> {
    const BEGIN: &[u8] = b"-----BEGIN ";
    const END: &[u8] = b"-----END ";
    const DASHES: &[u8] = b"-----";
    let find_dashes = |text: &[u8]| text.windows(DASHES.len()).position(|w| w == DASHES);

    let mut objects = Vec::new();
    // The selected object being read: its label and lines. The contents of
    // other objects are skipped, even when they are not terminated.
    let mut selected: Option<Object<'_>> = None;
    for line in pem.split(|&byte| matches!(byte, b'\r' | b'\n')) {
        let mut line = line
            .strip_prefix(b"\xef\xbb\xbf")
            .unwrap_or(line)
            .trim_ascii_end();
        if let Some(rest) = line.strip_prefix(END) {
            // Outside a selected object, a malformed end boundary is only text.
            // Text after an end boundary can only be the next begin boundary.
            let boundary = find_dashes(rest).map(|end| (&rest[..end], &rest[end + DASHES.len()..]));
            line = match boundary {
                Some((_, next)) if next.is_empty() || next.starts_with(BEGIN) => next,
                _ if selected.is_some() => return None,
                _ => b"",
            };
            if let Some((label, _)) = boundary
                && let Some((begin, lines)) = selected.take()
            {
                if begin != label {
                    return None;
                }
                objects.push((begin, lines));
                if first_only {
                    return Some(objects);
                }
            }
        }
        if let Some(rest) = line.strip_prefix(BEGIN) {
            if selected.is_some() {
                return None;
            }
            match rest.strip_suffix(DASHES) {
                Some(label) if find_dashes(label).is_none() => {
                    selected = select(label).then(|| (label, Vec::new()));
                }
                // A malformed begin boundary is an error if it names a selected
                // object, and otherwise only text.
                _ => {
                    if select(find_dashes(rest).map_or(rest, |end| &rest[..end])) {
                        return None;
                    }
                }
            }
        } else if let Some((_, lines)) = selected.as_mut() {
            // The PEM parsers also skip indentation. Base64 has no '-', so an
            // indented boundary is malformed data, not a boundary.
            let line = line.trim_ascii_start();
            if line.contains(&b'-') {
                return None;
            }
            if !line.is_empty() {
                lines.push(line);
            }
        }
    }
    selected.is_none().then_some(objects)
}

/// The DER certificates in `pem`, in order, or `None` if one is malformed.
///
/// Like OpenSSL's certificate reader, this reads the `CERTIFICATE` and legacy
/// `X509 CERTIFICATE` labels, skips other objects, including `TRUSTED
/// CERTIFICATE` ones, and ignores data that follows a certificate's DER.
pub(crate) fn pem_certificates(pem: &[u8]) -> Option<Vec<CertificateDer<'static>>> {
    let objects = pem_objects(
        pem,
        |label| label == b"CERTIFICATE" || label == b"X509 CERTIFICATE",
        false,
    )?;
    // Pass the base64 decoder only the selected objects, under the label it reads.
    let mut certificates = Vec::with_capacity(pem.len());
    for (_, lines) in &objects {
        certificates.extend_from_slice(b"-----BEGIN CERTIFICATE-----\n");
        for line in lines {
            certificates.extend_from_slice(line);
            certificates.push(b'\n');
        }
        certificates.extend_from_slice(b"-----END CERTIFICATE-----\n");
    }
    let certs = <(SectionKind, Vec<u8>)>::pem_slice_iter(&certificates)
        .map(|section| {
            let (_, mut der) = section.ok()?;
            der.truncate(der_sequence_len(&der)?);
            Some(CertificateDer::from(der))
        })
        .collect::<Option<Vec<_>>>()?;
    (certs.len() == objects.len()).then_some(certs)
}

/// The certificate chain of a PKCS#8 identity, which must not be empty.
#[cfg(any(
    feature = "rustls",
    feature = "openssl",
    not(all(target_vendor = "apple", not(target_os = "macos")))
))]
pub(crate) fn identity_certificates(pem: &[u8]) -> io::Result<Vec<CertificateDer<'static>>> {
    pem_certificates(pem)
        .filter(|certs| !certs.is_empty())
        .ok_or_else(invalid_identity_chain)
}

/// The error for a PKCS#8 identity without a valid certificate chain.
#[cfg(any(
    feature = "rustls",
    feature = "openssl",
    not(all(target_vendor = "apple", not(target_os = "macos")))
))]
pub(crate) fn invalid_identity_chain() -> io::Error {
    crate::invalid_data("PKCS#8 identity requires a valid PEM certificate chain")
}

/// The length of the complete DER SEQUENCE at the start of `der`.
fn der_sequence_len(der: &[u8]) -> Option<usize> {
    let (0x30, _, rest) = der_element(der)? else {
        return None;
    };
    Some(der.len() - rest.len())
}

/// Whether `der` has the shape of an X.509 certificate: a SEQUENCE holding a
/// to-be-signed SEQUENCE, a SEQUENCE and a BIT STRING, and nothing else, whose
/// to-be-signed part starts with an optional version, a serial number and five
/// SEQUENCEs (the signature algorithm, issuer, validity, subject and public
/// key). CRLs and certification requests have other shapes.
#[cfg(feature = "rustls")]
pub(crate) fn is_certificate(der: &[u8]) -> bool {
    /// The bytes after elements with these tags at the start of `der`.
    fn skip<'der>(der: &'der [u8], tags: &[u8]) -> Option<&'der [u8]> {
        tags.iter()
            .try_fold(der, |der, &tag| match der_element(der)? {
                (found, _, rest) if found == tag => Some(rest),
                _ => None,
            })
    }

    let Some((0x30, certificate, [])) = der_element(der) else {
        return false;
    };
    let Some((0x30, tbs, rest)) = der_element(certificate) else {
        return false;
    };
    let Some([]) = skip(rest, &[0x30, 0x03]) else {
        return false;
    };
    // The version is an EXPLICIT [0] element.
    let tbs = match der_element(tbs) {
        Some((0xa0, _, rest)) => rest,
        _ => tbs,
    };
    skip(tbs, &[0x02, 0x30, 0x30, 0x30, 0x30, 0x30]).is_some()
}

/// The tag, content and remaining bytes of the DER element at the start of
/// `der`, which must be complete.
fn der_element(der: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let (&tag, rest) = der.split_first()?;
    let (&length, rest) = rest.split_first()?;
    let (length, rest) = if length < 0x80 {
        (usize::from(length), rest)
    } else {
        let count = usize::from(length & 0x7f);
        if count == 0 || count > size_of::<usize>() {
            return None;
        }
        let (bytes, rest) = rest.split_at_checked(count)?;
        let length = bytes
            .iter()
            .fold(0, |length, &byte| (length << 8) | usize::from(byte));
        (length, rest)
    };
    let (content, rest) = rest.split_at_checked(length)?;
    Some((tag, content, rest))
}

/// The first PKCS#8, PKCS#1 or SEC1 private key object in `pem`, found with the
/// PEM boundary rules of this module, or `None` if there is none or it is
/// malformed. Later objects are not read.
#[cfg(feature = "rustls")]
pub(crate) fn pem_any_private_key(pem: &[u8]) -> Option<rustls_pki_types::PrivateKeyDer<'static>> {
    let objects = pem_objects(
        pem,
        |label| {
            matches!(
                label,
                b"PRIVATE KEY" | b"RSA PRIVATE KEY" | b"EC PRIVATE KEY"
            )
        },
        true,
    )?;
    let (label, lines) = objects.first()?;
    let mut key = b"-----BEGIN ".to_vec();
    key.extend_from_slice(label);
    key.extend_from_slice(b"-----\n");
    for line in lines {
        key.extend_from_slice(line);
        key.push(b'\n');
    }
    key.extend_from_slice(b"-----END ");
    key.extend_from_slice(label);
    key.extend_from_slice(b"-----\n");
    rustls_pki_types::PrivateKeyDer::from_pem_slice(&key).ok()
}

/// The DER of the first `PRIVATE KEY` object in `pem`, or `None` if there is
/// none or it is malformed. Like certificates, keys are found with the PEM
/// boundary rules of this module; later objects are not read. The buffers
/// holding the key are wiped.
#[cfg(all(
    feature = "native-tls",
    not(all(target_vendor = "apple", not(target_os = "macos")))
))]
pub(crate) fn pem_private_key(pem: &[u8]) -> Option<pkcs8::der::zeroize::Zeroizing<Vec<u8>>> {
    use pkcs8::der::zeroize::Zeroizing;

    const BEGIN: &[u8] = b"-----BEGIN PRIVATE KEY-----\n";
    const END: &[u8] = b"-----END PRIVATE KEY-----\n";

    let objects = pem_objects(pem, |label| label == b"PRIVATE KEY", true)?;
    let (_, lines) = objects.first()?;
    // The decoder below needs 64-column lines. Rewrap them in one allocation:
    // growing the buffer would free copies of the key unwiped.
    // Leave out any whitespace inside the lines, as the other parsers do.
    let base64 = || {
        lines
            .iter()
            .copied()
            .flatten()
            .filter(|byte| !byte.is_ascii_whitespace())
    };
    let base64_len = base64().count();
    let mut key = Zeroizing::new(Vec::with_capacity(
        BEGIN.len() + END.len() + base64_len + base64_len.div_ceil(64),
    ));
    key.extend_from_slice(BEGIN);
    for (index, &byte) in base64().enumerate() {
        key.push(byte);
        if index % 64 == 63 || index + 1 == base64_len {
            key.push(b'\n');
        }
    }
    key.extend_from_slice(END);
    // Unlike the certificate parser, this decoder keeps no copy of the base64
    // and writes the key into a single buffer, which is wiped even when the
    // decoding fails.
    let mut decoder = pkcs8::der::pem::Decoder::new(&key).ok()?;
    let mut der = Zeroizing::new(Vec::with_capacity(decoder.remaining_len()));
    decoder.decode_to_end(&mut der).ok()?;
    Some(der)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// PEM-encode `der` without depending on a backend's encoder.
    fn encode(label: &str, der: &[u8], line_ending: &str) -> String {
        const BASE64: &[u8; 64] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut text = Vec::new();
        for chunk in der.chunks(3) {
            let value = chunk
                .iter()
                .chain([0, 0].iter())
                .take(3)
                .fold(0u32, |value, &byte| (value << 8) | u32::from(byte));
            for index in 0..4 {
                text.push(if index <= chunk.len() {
                    BASE64[((value >> (18 - 6 * index)) & 63) as usize]
                } else {
                    b'='
                });
            }
        }
        let mut pem = format!("-----BEGIN {label}-----{line_ending}");
        for line in text.chunks(64) {
            pem.push_str(std::str::from_utf8(line).unwrap());
            pem.push_str(line_ending);
        }
        pem + &format!("-----END {label}-----{line_ending}")
    }

    /// Indent the lines of `pem` that are not boundaries.
    fn indent_body(pem: &str) -> String {
        pem.lines()
            .map(|line| {
                if line.starts_with("-----") {
                    format!("{line}\n")
                } else {
                    format!("  {line}\n")
                }
            })
            .collect()
    }

    /// `pem` with an indented copy of its end boundary, followed by text that is
    /// not base64, before the end boundary.
    fn indented_end(pem: &str) -> String {
        let end = pem.lines().last().unwrap();
        pem.replace(end, &format!("  {end}\n!!!! not base64 ~~~\n{end}"))
    }

    /// `pem` with text after its end boundary, which makes the boundary
    /// malformed.
    #[cfg(any(
        feature = "rustls",
        all(
            feature = "native-tls",
            not(all(target_vendor = "apple", not(target_os = "macos")))
        )
    ))]
    fn junk_after_end(pem: &str) -> String {
        let end = pem.lines().last().unwrap();
        pem.replace(end, &format!("{end} junk"))
    }

    fn chain() -> Vec<CertificateDer<'static>> {
        crate::tests::certificates(crate::tests::CERT_CHAIN)
    }

    /// The fixture chain under every certificate label, with mixed line endings,
    /// a byte order mark, and an encrypted key between the certificates, and the
    /// certificates read from it: the `TRUSTED CERTIFICATE` one is skipped.
    pub(crate) fn legacy_chain() -> (String, Vec<CertificateDer<'static>>) {
        let certs = chain();
        assert!(certs.len() >= 3);
        // An empty SEQUENCE stands in for the OpenSSL trust settings.
        let trusted = [certs[2].as_ref(), &[0x30, 0x00]].concat();
        let mut pem = "\u{feff}".to_owned()
            + &encode("CERTIFICATE", &certs[0], "\r\n")
            + "-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\n\
               DEK-Info: AES-128-CBC,00000000000000000000000000000000\n\nAAAA\n\
               -----END RSA PRIVATE KEY-----\n"
            + &encode("X509 CERTIFICATE", &certs[1], "\r")
            + &encode("TRUSTED CERTIFICATE", &trusted, "\n");
        for cert in &certs[3..] {
            pem += &encode("CERTIFICATE", cert, "\n");
        }
        let mut read = certs;
        read.remove(2);
        (pem, read)
    }

    #[test]
    fn reads_legacy_certificate_labels() {
        let (pem, certs) = legacy_chain();
        assert_eq!(pem_certificates(pem.as_bytes()).unwrap(), certs);
    }

    #[test]
    fn reads_joined_boundaries_and_skips_boundary_text() {
        let certs = chain();
        let first = encode("CERTIFICATE", &certs[0], "\n");
        let second = encode("CERTIFICATE", &certs[1], "\n");
        // Files concatenated without a final newline join the boundaries.
        let joined = first.trim_end().to_owned() + &second;
        assert_eq!(pem_certificates(joined.as_bytes()).unwrap(), &certs[..2]);
        // Boundaries start a line, so other text mentioning them is skipped.
        let commented = format!("# -----BEGIN CERTIFICATE----- blocks follow\n{first}");
        assert_eq!(pem_certificates(commented.as_bytes()).unwrap(), &certs[..1]);
    }

    #[cfg(any(
        feature = "rustls",
        feature = "openssl",
        not(all(target_vendor = "apple", not(target_os = "macos")))
    ))]
    #[test]
    fn identity_chains_need_a_certificate() {
        for pem in [
            "",
            "no certificates",
            "-----BEGIN PRIVATE KEY-----\n-----END PRIVATE KEY-----\n",
        ] {
            let error = identity_certificates(pem.as_bytes()).unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        }
    }

    #[cfg(feature = "rustls")]
    #[test]
    fn recognizes_certificates_by_shape() {
        assert!(chain().iter().all(|cert| is_certificate(cert)));
        let cert = chain()[0].to_vec();
        let key = crate::tests::pkcs8_key();
        let mut trailing = cert.clone();
        trailing.push(0);
        // The smallest certificate shape: tbs { [0] version, serial, five
        // SEQUENCEs }, a signature algorithm and a signature. A certification
        // request has the same outer shape, but its info is { version, subject,
        // key, [0] attributes }.
        let minimal = [
            0x30, 0x19, 0x30, 0x12, 0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x01, 0x01, 0x30, 0x00,
            0x30, 0x00, 0x30, 0x00, 0x30, 0x00, 0x30, 0x00, 0x30, 0x00, 0x03, 0x01, 0x00,
        ];
        let request = [
            0x30, 0x10, 0x30, 0x09, 0x02, 0x01, 0x00, 0x30, 0x00, 0x30, 0x00, 0xa0, 0x00, 0x30,
            0x00, 0x03, 0x01, 0x00,
        ];
        assert!(is_certificate(&minimal));
        for der in [
            &[0x30, 0x00][..],
            key.secret_pkcs8_der(),
            &trailing,
            &cert[..cert.len() - 1],
            &request,
        ] {
            assert!(!is_certificate(der));
        }
    }

    #[cfg(all(
        feature = "native-tls",
        not(all(target_vendor = "apple", not(target_os = "macos")))
    ))]
    #[test]
    fn finds_private_keys_with_the_certificate_rules() {
        let key = crate::tests::pkcs8_key();
        let cert = encode("CERTIFICATE", &chain()[0], "\n");
        let pem = std::str::from_utf8(crate::tests::PRIVATE_KEY).unwrap();
        // A byte order mark, files concatenated without a final newline, and
        // indentation.
        for input in [
            format!("\u{feff}{pem}"),
            cert.trim_end().to_owned() + pem,
            indent_body(pem),
        ] {
            assert_eq!(
                pem_private_key(input.as_bytes()).unwrap().as_slice(),
                key.secret_pkcs8_der()
            );
        }
        assert!(pem_private_key(cert.as_bytes()).is_none());
        let truncated = format!("{pem}-----BEGIN PRIVATE KEY-----\nAAAA\n");
        assert_eq!(
            pem_private_key(truncated.as_bytes()).unwrap().as_slice(),
            key.secret_pkcs8_der()
        );
        assert!(pem_private_key(indented_end(pem).as_bytes()).is_none());
        assert!(pem_private_key(junk_after_end(pem).as_bytes()).is_none());
    }

    #[cfg(feature = "rustls")]
    #[test]
    fn finds_any_private_key_with_the_certificate_rules() {
        let key =
            rustls_pki_types::PrivateKeyDer::from_pem_slice(crate::tests::PRIVATE_KEY).unwrap();
        let cert = encode("CERTIFICATE", &chain()[0], "\n");
        let pem = std::str::from_utf8(crate::tests::PRIVATE_KEY).unwrap();
        for input in [format!("\u{feff}{pem}"), cert.trim_end().to_owned() + pem] {
            assert_eq!(pem_any_private_key(input.as_bytes()).unwrap(), key);
        }
        assert!(pem_any_private_key(cert.as_bytes()).is_none());
        // Only the first key is read, as by the PEM key readers.
        let truncated = format!("{pem}-----BEGIN EC PRIVATE KEY-----\nAAAA\n");
        assert_eq!(pem_any_private_key(truncated.as_bytes()).unwrap(), key);
        assert!(pem_any_private_key(indented_end(pem).as_bytes()).is_none());
        assert!(pem_any_private_key(junk_after_end(pem).as_bytes()).is_none());
    }

    #[test]
    fn custom_roots_skip_trusted_certificates() {
        let certs = chain();
        let trusted = encode("TRUSTED CERTIFICATE", &certs[0], "\n");
        assert!(custom_roots(&trusted).unwrap().is_empty());
        let legacy = encode("X509 CERTIFICATE", &certs[1], "\n");
        assert_eq!(custom_roots(&(trusted + &legacy)).unwrap(), &certs[1..2]);
    }

    #[test]
    fn ignores_data_after_a_certificate() {
        let certs = chain();
        let padded = [certs[0].as_ref(), &[0x00]].concat();
        let pem = encode("CERTIFICATE", &padded, "\n");
        assert_eq!(pem_certificates(pem.as_bytes()).unwrap(), &certs[..1]);
    }

    #[test]
    fn rejects_malformed_certificates() {
        for der in [
            &[][..],
            &[0x30],
            &[0x30, 0x82, 0x01],
            &[0x31, 0x00],
            &[0x30, 0x05, 0x00],
        ] {
            let pem = encode("CERTIFICATE", der, "\n");
            assert!(pem_certificates(pem.as_bytes()).is_none(), "{der:?}");
        }
        let cert = encode("CERTIFICATE", &chain()[0], "\n");
        for malformed in [
            // Unterminated, nested, or encrypted certificates.
            cert.replace("-----END CERTIFICATE-----\n", ""),
            cert.replacen("\n", "\n-----BEGIN CERTIFICATE-----\n", 1),
            cert.replacen("\n", "\nProc-Type: 4,ENCRYPTED\n", 1),
            // An indented boundary is data, not the end of the object.
            indented_end(&cert),
            // Malformed boundaries.
            cert.replacen("-----\n", "-----\x0b\n", 1),
            cert.replacen("-----\n", "----- junk\n", 1),
            cert.replace("-----END CERTIFICATE-----", "-----END CERTIFICATE"),
            cert.replace(
                "-----END CERTIFICATE-----",
                "-----END CERTIFICATE----- junk",
            ),
        ] {
            assert!(
                pem_certificates(malformed.as_bytes()).is_none(),
                "{malformed}"
            );
        }
        assert!(pem_certificates(b"-----BEGIN CERTIFICATE-----\nAAAA\n").is_none());
        // Malformed boundaries outside an object are only text, as is
        // indentation inside one.
        let separated = format!(
            "-----BEGIN OF BUNDLE\n-----END OF BUNDLE\n{}-----END-----junk\n",
            indent_body(&cert)
        );
        assert_eq!(
            pem_certificates(separated.as_bytes()).unwrap(),
            &chain()[..1]
        );
    }
}
