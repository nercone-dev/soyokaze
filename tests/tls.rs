use bytes::Bytes;

use soyokaze::tls;
use soyokaze::helpers::base64;
use soyokaze::models::{Body, ConnectionID, Message, Method, Port, Security, Version};
use soyokaze::protocol::base::{AnyConnection, Connection};
use soyokaze::{Client, ClientConfig, Format, Handler, Identity, Server, ServerConfig};

/// An EC P-256 key in SEC1 (RFC 5915), as `openssl ecparam -genkey` writes it.
const EC_SEC1: &str = "\
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIHyYjIFy/CCe4TwdFelEv7GTH+7AY2VKDO3gDwAMTvzzoAoGCCqGSM49
AwEHoUQDQgAEpiwYdctR4uKgpGUmlR3HliQLGYfZtUrfBCaA77URgnedOTE8AziK
vbz6kBDdCEd6krzz10hZYC6t+eyfRrNecg==
-----END EC PRIVATE KEY-----
";

/// The self-signed certificate that goes with [`EC_SEC1`].
const LEAF: &str = "\
-----BEGIN CERTIFICATE-----
MIIBhjCCAS2gAwIBAgIUKveDsAApkVlgjHPF3D4GbSwirygwCgYIKoZIzj0EAwIw
GDEWMBQGA1UEAwwNc295b2themUudGVzdDAgFw0yNjA4MDIxNzUzMTFaGA8yMTI2
MDcwOTE3NTMxMVowGDEWMBQGA1UEAwwNc295b2themUudGVzdDBZMBMGByqGSM49
AgEGCCqGSM49AwEHA0IABKYsGHXLUeLioKRlJpUdx5YkCxmH2bVK3wQmgO+1EYJ3
nTkxPAM4ir28+pAQ3QhHepK889dIWWAurfnsn0azXnKjUzBRMB0GA1UdDgQWBBQm
WKtlF4GuC7aNtmL8yt0rh/wiwDAfBgNVHSMEGDAWgBQmWKtlF4GuC7aNtmL8yt0r
h/wiwDAPBgNVHRMBAf8EBTADAQH/MAoGCCqGSM49BAMCA0cAMEQCIBRwzGjXaBnQ
XDJOnnrX9dO/RRyqVVKYeVHaTAv/1uqAAiAQZTRqjcuCBK5ls3CqHHQOxQaegDP2
H+mvYUXE+GqDIw==
-----END CERTIFICATE-----
";

/// An RSA key in PKCS#1 (RFC 8017), as `openssl genrsa -traditional` writes it.
const RSA_PKCS1: &str = "\
-----BEGIN RSA PRIVATE KEY-----
MIIEpQIBAAKCAQEA2SuFqD1HOmLN+GbT4BrBrz286ltwsN4os0QxHEGqlg72Tcsb
gnoaWoEJ5Uc+R5zQDl75vjaFaH6AoxyIeGrk1SBj9OqcSODMokw3p5fbRu9JF2p4
zOFdu+5rMOubYtmeXG6vlG1xisS0rv+DseeVb3TIhdPeFEliEvAIQMuK7QXwAlCK
XEGMxJSQNoC78vGUZikO6phi26RQGJeCSo++CvFmf932TyaO1u/dBGNomQZhACER
o3xfnGOlkwjSpee/1kFfw58Jht8ZJGLtueD9WkS1Kwx2lygg81nDjzL6nrTkT4ZN
dyKTuWC7f3JNmdhhe7xKzalTFXjJcwAHzKRkoQIDAQABAoIBADIWKpZZw7LAlPaE
aLtYEHGlUIvQmRYBtutZf+YfcwN24fGhNXALT0auWiTqIIANt6KI3xqyomQuQObd
rs/u/2X0OXmEHpVkW23XHELn8CfVCkt/P+so0yCD5W779/N9c1uoH5ChCT3TDkUK
I0qFud5h1dmfuql9H0R03cJr71eoySFlBNDF/nxLuzw9x/iHRVkmTpwUnorUBhNx
J5CHHNdjfk96gk1jn6wFdeZHV93YIWR5gSHkW7XbBKSPPpXN1CF9Eq7rQk7k9att
aQGmoidgT9yFyFJEzfEzLlmPFfMW2pb33WHGxxRfp2HsrKQ7SfTAcdCKNiChHAnq
hioTru0CgYEA8BSqt6woAYBOmmTbtnJ+BuLpv2dAVXVBV3tPmIjridSLflOUK63z
CLFWWAvzOsJhpNfYFWNus2sHPqgbXFGUkbjjoTHw6uU8DK4RAzdx0OH2DcvhN35c
//ZO6YRBuBybOo24VBBwP1SBrSP1N/kJLC/zY5tHrxT9WRguOOFqOS8CgYEA55Hz
BHf9x7npqZqMgqSF0BE3sW9nywRYwob4obrA7Cv1lkixwOA1HXMRAo+2t+vQh5NC
gVU//6dhnDDt6sTp8+oYUUaiU+l6dWEUcesXzMswKdsVsESOWyHpaL1l9nnSS/sc
b8L/4sMpwGeDRhYDa9T3Wej+ZYH6IcR6lRHHKy8CgYEAk42wKvjVEa8hIEUywFx3
1pWp4ih8YsmRIko4bmBgmzKVlUua+omLoGEV10Fo+Uk0qBK8zNBy3jS+nCTHxCKj
tDg1NwIxtryy/nwRGq/99Mqb5njS779rOynP8DeICLcUNJWbn5cG1fWDSb2a3g7i
M1U5OpPaJ+I3n4V8CxuHpKMCgYEAgBKSS0hpzUqfVrQpPh/r+hVrrfClgPzYck3f
uOLmzDfLzeBKnxfhiHYZVEdTkQkU/caOI6WYjbZvH8lX7F4X3lT8OgdMxAf/OGgG
vLJ/KT6/VobayfBAo1pwEwOdHuJlUqyBH7bDexDhSI53Zg3KuprAarOX72AhjQdz
nHqGovUCgYEA7I1ui7o4seTBkJvhLLsw4PVhkr5Bz6yPAVX4/vS2NnUJGiEdYJdv
xESWfbkJCe05GlmVMpSdFAdsPktqfJVd5TBtuk77U/N0D8Ukw1unlQ6tpO5QGhdW
ZOt+o+NqXZflu3bBUSWqIJXMHtI75kc9TmCVowSl85NGlva3sFKTwbg=
-----END RSA PRIVATE KEY-----
";

/// [`EC_SEC1`] wrapped as an encrypted PKCS#8 (RFC 5958) under `secret`.
const EC_PKCS8_ENCRYPTED: &str = "\
-----BEGIN ENCRYPTED PRIVATE KEY-----
MIH0MF8GCSqGSIb3DQEFDTBSMDEGCSqGSIb3DQEFDDAkBBCH4/sypM0xae3VzlDf
pJHpAgIIADAMBggqhkiG9w0CCQUAMB0GCWCGSAFlAwQBKgQQMzvQxYERHJkbvcX3
Rc1KKwSBkG1pq7QqEsHdhMCCw8+t2mHU8jjKUPmr8JCbE8qRiC1HE7TRJGqeueSg
1pCbU808yk04QvNTn29dS4pcQqkt1CQ5HHG/3UVpREO1DMBJt9mk6Tl0lbnFXPu/
OX3InOHdgNGBp33I6ACxjwdSN0UWt/c0UVYrGMg8/wX5UHCcj1V4+IG7PEJIBKS4
T65YDPy2Ig==
-----END ENCRYPTED PRIVATE KEY-----
";

/// [`LEAF`] and [`EC_SEC1`] in one PKCS#12 (RFC 7292) archive, under `secret`.
const BUNDLE_PKCS12: &str = "MIIENAIBAzCCA+IGCSqGSIb3DQEHAaCCA9MEggPPMIIDyzCCAnoGCSqGSIb3DQEHBqCCAmswggJnAgEAMIICYAYJKoZIhvcNAQcBMF8GCSqGSIb3DQEFDTBSMDEGCSqGSIb3DQEFDDAkBBCUNEC4zEmJ41N3Vl7AiXsGAgIIADAMBggqhkiG9w0CCQUAMB0GCWCGSAFlAwQBKgQQACuXWr08LYQwgkkWasN97ICCAfDjCOsreOnVAEyCQaRHOfFyigp7nhgtEkmmc80jdI+DS+J5uvq6FuX9ewLLkC0aXWsrkSff5B5/wi00iosHcwwrU8ZPUfXJuEmcu01ayRWsv9nyl5rTjV5gduy6vSRJbQvqqDozAcx/ndjNxK5dODYXF7FqB5mVUAQ6vZVUlTKxZuIsxA/CiL0AjR7sEpiLrSkKnbb37NIYcxcLJyXg9tkYinwbIJQV5IymWCaHlZgjOtoZipnXx/gLKdp/e9OdgmXsg2ThZBM3/s0sXqF/Y3SzzsAaR4SV8qzKFGxyu0FcOBN6V8hHZNaHq6YS2MXxKVij8ARB58xWyWTz4gSwpNSd8QhnP9BDiOeFbBiRB/qshMPuXYOGUOseq7FmQicYdZ4XZxzMn49K2W1Vo/jgS+/AsUe/bXJTGuEW1XC0vfdyX47QYF0G8DSgQ4qFCR1HXB6aVgKIi77O66AT0GUODVzK5ldLUzWa8//jTwYGyDFjxRTNG5XMRq1pSiIKI7xlo0DOUvsDke85eA2qj295VkWpv+sRS6jy3Ig4xsVRQ5Y2SKHEswUjovwuyF5RYlsD8I/RYUY2sBs4Wsnn+os0Pc1tcnK4nb7OLltGeI98Mkl3GiM0xKyYYCXagnTA0AGwCYfC+Y5B8PzKy9YPStu7sSToMIIBSQYJKoZIhvcNAQcBoIIBOgSCATYwggEyMIIBLgYLKoZIhvcNAQwKAQKggfcwgfQwXwYJKoZIhvcNAQUNMFIwMQYJKoZIhvcNAQUMMCQEEKAsi4EivbMUocEi74jx9lQCAggAMAwGCCqGSIb3DQIJBQAwHQYJYIZIAWUDBAEqBBBocVMTYO7KlAzy38H7eARnBIGQse55ck7FveNIyH8mfq9hWFvwwCUQO0+0Sm5PER3eiZ7sbB8Vxyp/kU/GMtaTE7SWVZYl46EGhUFGh4NC9aczKDJjEjf7IKZ5Uj6frVZ3bTto3eHOmNVQ21Mg4viZxEwfvpybAwQu2PHNRIkln7CfgRW9K29DGslnta21htGmtJ864zOPMWkU8xXQW/UDTNVnMSUwIwYJKoZIhvcNAQkVMRYEFPjOZP2g2vegnGxrqGWEoGKbSsZCMEkwMTANBglghkgBZQMEAgEFAAQgenvVTsPaX4oOFa9bpBD5N1dtUcv+Q9BzPBNB346N6GoEELbCNsnlWqYbZLOG7mAQo+ICAggA";

/// A CA, and [`EC_SEC1`]'s certificate reissued under it.
const CA: &str = "\
-----BEGIN CERTIFICATE-----
MIIBgzCCASmgAwIBAgIUcRHrCPtovUoYigALx9j5Yk8OfjEwCgYIKoZIzj0EAwIw
FjEUMBIGA1UEAwwLc295b2themUuY2EwIBcNMjYwODAyMTgwMjQ3WhgPMjEyNjA3
MDkxODAyNDdaMBYxFDASBgNVBAMMC3NveW9rYXplLmNhMFkwEwYHKoZIzj0CAQYI
KoZIzj0DAQcDQgAE+06AjUgXRUCjcIOi6N8cEU6IwdB6qn8ifnFCoPtsG3Z2Q4lM
nDdo+6pGs2FZUMPwKTBApVI6Zd0YHiM6RDm5jKNTMFEwHQYDVR0OBBYEFAoy50Kj
A1FHPifMxw2qUbgUkkswMB8GA1UdIwQYMBaAFAoy50KjA1FHPifMxw2qUbgUkksw
MA8GA1UdEwEB/wQFMAMBAf8wCgYIKoZIzj0EAwIDSAAwRQIgPkeOB/nmdAYP+3M+
WdqpsvU05uyn71De7V/fOLRvdCkCIQCciBvuZwKGte8/P3SMHlbyUszd1icYFv6P
qGSiWB6Ygg==
-----END CERTIFICATE-----
";

const SIGNED_LEAF: &str = "\
-----BEGIN CERTIFICATE-----
MIIBczCCARqgAwIBAgIUb5V3kbln3c5IrGP8yMzlqMTblUowCgYIKoZIzj0EAwIw
FjEUMBIGA1UEAwwLc295b2themUuY2EwIBcNMjYwODAyMTgwMjQ3WhgPMjEyNjA3
MDkxODAyNDdaMBgxFjAUBgNVBAMMDXNveW9rYXplLnRlc3QwWTATBgcqhkjOPQIB
BggqhkjOPQMBBwNCAASmLBh1y1Hi4qCkZSaVHceWJAsZh9m1St8EJoDvtRGCd505
MTwDOIq9vPqQEN0IR3qSvPPXSFlgLq357J9Gs15yo0IwQDAdBgNVHQ4EFgQUJlir
ZReBrgu2jbZi/MrdK4f8IsAwHwYDVR0jBBgwFoAUCjLnQqMDUUc+J8zHDapRuBSS
SzAwCgYIKoZIzj0EAwIDRwAwRAIgYGNLwCa845/C7j8dZJkE41u9Kkyuqblwq+b9
YZyOi3MCID6xOnLgxJEM7q/NTM1B2mSKOi2yBFeypvm46h50NIgi
-----END CERTIFICATE-----
";

/// [`SIGNED_LEAF`], [`CA`] and [`EC_SEC1`] in one archive, under `secret`.
const CHAINED_PKCS12: &str = "MIIF1AIBAzCCBYIGCSqGSIb3DQEHAaCCBXMEggVvMIIFazCCBBoGCSqGSIb3DQEHBqCCBAswggQHAgEAMIIEAAYJKoZIhvcNAQcBMF8GCSqGSIb3DQEFDTBSMDEGCSqGSIb3DQEFDDAkBBCtNbR/QpbSxPTBghkVkdfWAgIIADAMBggqhkiG9w0CCQUAMB0GCWCGSAFlAwQBKgQQfP9lCC3bU8nb4KO+j5MnjoCCA5AmEo6UEOh+DNTROCedBAwQuzsgVUrED/FMwr8hO4gmeCvgjuAQMBjDay0aaJaZqO2nAA/a+/gVGMjyc2IqLlIIfucisZMFh5qnBu0mL2FhUljbdbm+F1rXMku1+VUgWvH9xvUbk4LEDST7EzbsIYDFZcYBxSHXwt5hGSXck7gUcRmNK23FUMvL3XK6/1cW7g7E0JQd5FLh47JH2uyOJ0yUKX1jFkMVhP12b8+O9WaNPy17i7M2YU20KSWTrVL7CZNVNbzDF+LgKiy5muhZwP0HD/QNw8gRvqqTlCOk8hK9O765OxOe11+lFI+rST96qxKTjtkzzlsBcs7ajj8Xv/ie3+AbGry5qdSTGX9755xcyxp1o7m89NdV9qpDxzNeHH4Wqj8tfK2L8WbjV4UYB6rOwM3VQzNdPOf+B0CFKPetT24MQO2bCkclTN34AYuBHjo6RPqqTt+/zAdBGRcEj/+0MURvy4Mv/IlTpTroKFqws6mrqh9/ANYmv9F5q7nVL2dgRQ48r4+xB4Yex+0uW6Ki5uSy6forp22YQFkDUENext/PMjQ39ustl9V31+nk+kb7w2SUPoN4+D62t7o4ZuDYB3tjb3PzF4c9qTdgOoIpH1TBP9kVFti5kTRiFUXm9AAg/bZnK6qZocNwMnRQ+abZZb/tI0e+rxIIsDDULBctWKxhOWzEphv6kIPtYX1RHjkMhYeVEqITQKQ9jUVYWdFX/nAmVwEil4Bpe6WbhPPLD8IwK8HGin2W6oH88u+sNtoLCk7hCcV52VYXz/eA3nTU2u9ZNaFf6UKxj6cdePsDg235YZckkj1ZJSa2beiOiLdcSMchpN5DpNs/7WLr6YbzwghzQnK/nEi4oH35frZ+WOHm0sIgaOKn/u8aj16cOkllQbYBBBaSGZMqKlnYZ6Rdk/lNZ6VorP7lGZftwSQvR+g0dLlkMPBM7RlQ5HGPIosm4/edEbLqXHlx/MuQz42NzGKlDiW3QWcgNoMTRqsXd7A4cySyhbYHsmmttM0cHk88u9Yf6MyewaGKkhsPbDZBtgXpp9PMAuvaIA1fiZACIHxOTfiDdDUaG4J4vp3hJXwBV1IrhVTk2GNlO69S2I4ZKI1SGqopSQAeUUpc2209Z6c4N4R9Sjy3Ddosh19AFlDk+GKSbAOitCYKbJCuvRmHA/ca3GD5oKYqy6Et4BuJqdhMS/uDEiZ+UMxzbuLH7tEwggFJBgkqhkiG9w0BBwGgggE6BIIBNjCCATIwggEuBgsqhkiG9w0BDAoBAqCB9zCB9DBfBgkqhkiG9w0BBQ0wUjAxBgkqhkiG9w0BBQwwJAQQriyQnUg2AW4qO+/g3cmkWAICCAAwDAYIKoZIhvcNAgkFADAdBglghkgBZQMEASoEEOdZLFwP6KdXK22acvADUPcEgZBRbGGb6uG1DUSp4vbUqoHT7qcUV7rU5hCU14HRc+33RX2vOPbf536En+kYEzdLmHZrXhmX38DhuL8p5PjW5WFFPpfwgYhDVE5jlGo7yp1lXpWbSFB6ivwY/cQ0Bd9mTlRFxL9+p+6cdq6QjP1zfNlxIhvUWtalm4Jpqz1CNAyWXAG2yz2jxAvcY5mUECC08VsxJTAjBgkqhkiG9w0BCRUxFgQUzBCM1pI+Ur5aM/KhDc/fW+jeJI0wSTAxMA0GCWCGSAFlAwQCAQUABCD7s/zfgXrKgjf6+yB7hKxyajeXMiEU5kE59Zwm6JjS4QQQ481FRZ9RHZAXUnvDsTVlOQICCAA=";

/// [`LEAF`] with no key beside it, which is a legal archive but no identity.
const CERT_ONLY_PKCS12: &str = "MIICtwIBAzCCAmUGCSqGSIb3DQEHAaCCAlYEggJSMIICTjCCAkoGCSqGSIb3DQEHBqCCAjswggI3AgEAMIICMAYJKoZIhvcNAQcBMF8GCSqGSIb3DQEFDTBSMDEGCSqGSIb3DQEFDDAkBBBxrYPGovDnKH+FkiznOS9RAgIIADAMBggqhkiG9w0CCQUAMB0GCWCGSAFlAwQBKgQQluh2vzqEpOvhVKQ+2dWbqICCAcADFHowhPVYVBWwSKuj3AaJjPiHdfXT6THM22sccc+3usi0EzOt+HWYBS5Oi22iiOoTenFthAS0BfxG2nCIHd3onlmfL5pHNfl5keXDMYpjHI/o1Cs3Zb+VdzSOJvKvDRkgYZM+ISZ1/Uc55kIsOs3xZQnxZJZEptmIeNojZowIaxzriB6PLywxVhwDkK7Ga0XZ5uQDuNzDj5Ni+crD1jGJMJpWwgif6ofJAOKOoHmOpwOCFN629lKAhRGfMJR51cfbo2xveHjpQi8MiRehloAaOCZwNKsU0mBzLzxNFOkalPFJCesPhf1j/54gpwi+UUCkr3DWcK1P5ZsA1XKDiFb4KTTHtAygQ/CeTvkCpb2wVDTh6J2MMX73uUs+QOWDOyTfhUtZXtUY2uGfVqvsE8uOK96hPRSNtsmoWQTztcqogkDZX8YMF1xPAo/JUkixWi6dtcR4xwIX1FUj5/jXKSwESG6BMD/L3D6dsx9nWQ6AG7IQUt2w1FfHw7pVIomcUND5k4piVZ0MeIH9vVs2jk6jVfKKC2v9H7OSVvi4rvmXnWWCox/nJ79v0b6ayMI2w2BO80AY6hP/Bzww2mzfOAGmMEkwMTANBglghkgBZQMEAgEFAAQgSRF2pBvdxCN41UDObMTFIumyMo6pI6HWj5IQJ0l7IkwEEKaDgvvbWmhRhi3IQ0tlSJUCAggA";

/// The DER a PEM section carries, so one piece of test material serves both.
///
/// This is the RFC 7468 encoding in reverse: drop the encapsulation
/// boundaries, run the lines together and undo the Base64.
fn der(pem: &str) -> Vec<u8> {
    let body: String = pem
        .lines()
        .skip_while(|line| !line.starts_with("-----BEGIN"))
        .skip(1)
        .take_while(|line| !line.starts_with("-----END"))
        .collect();

    base64::decode(&body).expect("the test material is not PEM")
}

/// A freshly issued certificate and its key, in both formats.
struct Issued {
    certificate_pem: String,
    certificate_der: Vec<u8>,
    key_pem: String,
    key_der: Vec<u8>,
}

fn issue(name: &str) -> Issued {
    let issued = rcgen::generate_simple_self_signed(vec![name.to_owned()]).expect("no certificate");

    Issued {
        certificate_pem: issued.cert.pem(),
        certificate_der: issued.cert.der().to_vec(),
        key_pem: issued.signing_key.serialize_pem(),
        key_der: issued.signing_key.serialize_der(),
    }
}

/// The DER of every certificate in a parsed chain, for comparing chains.
fn chain_der(chain: &[boring::x509::X509]) -> Vec<Vec<u8>> {
    chain.iter().map(|certificate| certificate.to_der().expect("a parsed certificate did not re-encode")).collect()
}

#[test]
fn a_format_is_told_from_the_first_byte_that_is_not_whitespace() {
    assert_eq!(Format::SEQUENCE, 0x30);

    for pem in [LEAF, EC_SEC1, RSA_PKCS1, EC_PKCS8_ENCRYPTED] {
        assert_eq!(Format::of(&der(pem)), Format::Der, "DER was not recognised");
        assert_eq!(Format::of(pem.as_bytes()), Format::Pem, "PEM was not recognised");
        assert_eq!(der(pem)[0], Format::SEQUENCE, "the test material is not a DER SEQUENCE");
    }

    assert_eq!(Format::of(&base64::decode(BUNDLE_PKCS12).expect("the archive is not Base64")), Format::Der);
}

#[test]
fn pem_is_recognised_when_something_precedes_its_armour() {
    let described = format!("Subject: CN=soyokaze.test\nIssuer: CN=soyokaze.test\n\n{LEAF}");
    assert_eq!(Format::of(described.as_bytes()), Format::Pem);
    assert_eq!(tls::certificates(described.as_bytes()).expect("described PEM did not parse").len(), 1);

    let indented = format!("\n\n\t{LEAF}");
    assert_eq!(Format::of(indented.as_bytes()), Format::Pem);
}

#[test]
fn a_certificate_reads_the_same_from_der_and_from_pem() {
    let from_der = tls::certificates(&der(LEAF)).expect("the DER certificate did not parse");
    let from_pem = tls::certificates(LEAF.as_bytes()).expect("the PEM certificate did not parse");

    assert_eq!(chain_der(&from_der).len(), 1, "one DER blob carries exactly one certificate");
    assert_eq!(chain_der(&from_der), chain_der(&from_pem));
}

#[test]
fn a_pem_bundle_carries_every_certificate_in_the_order_written() {
    let issued: Vec<Issued> = ["leaf.test", "intermediate.test", "root.test"].map(issue).into_iter().collect();
    let bundle: String = issued.iter().map(|one| one.certificate_pem.as_str()).collect();

    let parsed = tls::certificates(bundle.as_bytes()).expect("the bundle did not parse");
    let expected: Vec<Vec<u8>> = issued.iter().map(|one| one.certificate_der.clone()).collect();

    assert_eq!(chain_der(&parsed), expected);
}

#[test]
fn a_pem_blob_holding_a_key_beside_its_chain_reads_as_the_chain() {
    let together = format!("{EC_SEC1}{LEAF}");
    let parsed = tls::certificates(together.as_bytes()).expect("the combined file did not parse");

    assert_eq!(chain_der(&parsed), vec![der(LEAF)]);
}

#[test]
fn a_pem_blob_with_no_certificate_is_refused() {
    assert!(tls::certificates(EC_SEC1.as_bytes()).is_err(), "a key alone is not a chain");
    assert!(tls::certificates(b"not a certificate").is_err());
    assert!(tls::certificates(b"").is_err());
}

#[test]
fn a_der_blob_that_is_not_a_certificate_is_refused() {
    assert!(tls::certificates(&der(EC_SEC1)).is_err(), "a key is not a certificate");
    assert!(tls::certificates(&[Format::SEQUENCE, 0x01, 0x00]).is_err());
}

#[test]
fn a_chain_may_be_split_across_blobs_in_any_mixture_of_formats() {
    let leaf = issue("leaf.test");
    let intermediate = issue("intermediate.test");
    let root = issue("root.test");

    let bundled = format!("{}{}", intermediate.certificate_pem, root.certificate_pem);
    let mixed = vec![leaf.certificate_der.clone(), bundled.into_bytes()];
    let apiece = vec![
        leaf.certificate_pem.clone().into_bytes(),
        intermediate.certificate_der.clone(),
        root.certificate_pem.clone().into_bytes(),
    ];

    let expected = vec![leaf.certificate_der, intermediate.certificate_der, root.certificate_der];

    assert_eq!(chain_der(&tls::certificate_list(&mixed).expect("the mixed chain did not parse")), expected);
    assert_eq!(chain_der(&tls::certificate_list(&apiece).expect("the split chain did not parse")), expected);
}

#[test]
fn a_key_reads_the_same_from_der_and_from_pem() {
    let pkcs8 = issue("localhost");

    for (pem, der) in [(pkcs8.key_pem.as_str(), pkcs8.key_der.clone()), (RSA_PKCS1, der(RSA_PKCS1)), (EC_SEC1, der(EC_SEC1))] {
        let from_der = tls::private_key(&der).expect("the DER key did not parse");
        let from_pem = tls::private_key(pem.as_bytes()).expect("the PEM key did not parse");

        assert_eq!(
            from_der.public_key_to_der().expect("the DER key did not re-encode"),
            from_pem.public_key_to_der().expect("the PEM key did not re-encode"),
            "the two encodings gave different keys",
        );
    }
}

#[test]
fn one_file_holding_a_certificate_and_its_key_serves_as_both() {
    let combined = format!("{LEAF}{EC_SEC1}");

    let chain = tls::certificates(combined.as_bytes()).expect("the chain did not parse");
    assert_eq!(chain_der(&chain), vec![der(LEAF)]);

    let key = tls::private_key(combined.as_bytes()).expect("the key did not parse");
    let expected = tls::private_key(EC_SEC1.as_bytes()).expect("the reference key did not parse");
    assert_eq!(
        key.public_key_to_der().expect("the combined key did not re-encode"),
        expected.public_key_to_der().expect("the reference key did not re-encode"),
    );
}

#[test]
fn an_encrypted_key_is_refused_rather_than_guessed_at() {
    assert!(tls::private_key(EC_PKCS8_ENCRYPTED.as_bytes()).is_err());
    assert!(tls::private_key(&der(EC_PKCS8_ENCRYPTED)).is_err());
}

#[test]
fn a_blob_that_is_not_a_key_is_refused() {
    assert!(tls::private_key(LEAF.as_bytes()).is_err(), "a certificate is not a key");
    assert!(tls::private_key(&der(LEAF)).is_err());
    assert!(tls::private_key(b"").is_err());
}

#[test]
fn a_pkcs12_archive_gives_back_the_certificate_and_key_it_carries() {
    let archive = base64::decode(BUNDLE_PKCS12).expect("the archive is not Base64");
    let identity = Identity::from_pkcs12(&archive, "secret").expect("the archive did not open");

    let chain = identity.chain().expect("the chain did not parse");
    assert_eq!(chain_der(&chain), vec![der(LEAF)], "the leaf did not come back");

    let key = identity.private_key().expect("the key did not parse");
    let expected = tls::private_key(EC_SEC1.as_bytes()).expect("the reference key did not parse");
    assert_eq!(
        key.public_key_to_der().expect("the archived key did not re-encode"),
        expected.public_key_to_der().expect("the reference key did not re-encode"),
        "the archive gave back a different key",
    );
}

#[test]
fn a_pkcs12_archive_gives_its_leaf_first_and_never_twice() {
    let archive = base64::decode(CHAINED_PKCS12).expect("the archive is not Base64");
    let identity = Identity::from_pkcs12(&archive, "secret").expect("the archive did not open");

    let chain = identity.chain().expect("the chain did not parse");
    assert_eq!(chain_der(&chain), vec![der(SIGNED_LEAF), der(CA)]);
}

#[test]
fn a_pkcs12_archive_will_not_open_under_the_wrong_passphrase() {
    let archive = base64::decode(BUNDLE_PKCS12).expect("the archive is not Base64");

    assert!(Identity::from_pkcs12(&archive, "").is_err());
    assert!(Identity::from_pkcs12(&archive, "wrong").is_err());
    assert!(Identity::from_pkcs12(b"not an archive", "secret").is_err());
}

#[test]
fn a_pkcs12_archive_carrying_no_key_is_refused() {
    let archive = base64::decode(CERT_ONLY_PKCS12).expect("the archive is not Base64");

    assert!(Identity::from_pkcs12(&archive, "secret").is_err());
}

#[derive(Clone)]
struct Echo;

impl Handler for Echo {
    async fn on_connection(&self, connection: AnyConnection) {
        let mut connection = connection;

        while let Ok(request) = connection.receive().await {
            let mut response = Message::response(200, connection.version());
            response.stream_id = request.stream_id;
            response.body = Some(Body::Data(Bytes::from_static(b"Hello, World!")));

            if connection.send(response).await.is_err() || !connection.reusable() {
                break;
            }
        }

        connection.close().await;
    }
}

fn exchange(identity: Identity, roots: Vec<Vec<u8>>, version: Version, port: Port) -> Message {
    let server = Server::new(ServerConfig { versions: vec![version], identity: Some(identity), ..ServerConfig::default() });

    let cluster = server.run(Echo, std::slice::from_ref(&port), 1).expect("the port did not open");
    let address = cluster.address().expect("the cluster has no address");

    let runtime = tokio::runtime::Builder::new_multi_thread().enable_all().build().expect("no runtime");

    let response = runtime.block_on(async move {
        let client = Client::new(ClientConfig { versions: vec![version], roots: Some(roots), ..ClientConfig::default() });

        let target = match port {
            Port::QUIC(_) => Port::QUIC(address.port()),
            _ => Port::TCP(address.port()),
        };

        let mut connection = client.connect("localhost", target).await.expect("the client could not reach the server");
        let request = Message::request(Method::GET, "/index.html", version);

        let response = tokio::time::timeout(std::time::Duration::from_secs(10), client.request(&mut connection, request))
            .await
            .expect("the server did not answer")
            .expect("the exchange failed");

        connection.close().await;
        response
    });

    cluster.close(Some(1.0));
    response
}

#[test]
fn a_pem_identity_and_a_pem_root_serve_tls() {
    let issued = issue("localhost");

    let identity = Identity::new(vec![issued.certificate_pem.into_bytes()], issued.key_pem.into_bytes());
    let response = exchange(identity, vec![issued.certificate_der], Version::V2_0, Port::TCP(0));

    assert_eq!(response.status_code, Some(200));
    assert_eq!(response.body.as_ref().and_then(Body::inline), Some(Bytes::from_static(b"Hello, World!")));
}

#[test]
fn a_pem_identity_and_a_pem_root_serve_quic() {
    let issued = issue("localhost");

    let identity = Identity::new(vec![issued.certificate_pem.clone().into_bytes()], issued.key_pem.into_bytes());
    let response = exchange(identity, vec![issued.certificate_pem.into_bytes()], Version::V3_0, Port::QUIC(0));

    assert_eq!(response.status_code, Some(200));
    assert_eq!(response.body.as_ref().and_then(Body::inline), Some(Bytes::from_static(b"Hello, World!")));
}

/// RFC 8446 §4.1.2: TLS 1.3 puts 0x0304 in the `supported_versions` extension,
/// which is what a session reports as its version.
const TLS_1_3: u16 = 0x0304;

#[test]
fn a_message_over_tls_carries_what_the_handshake_settled() {
    for version in [Version::V1_1, Version::V2_0] {
        let issued = issue("localhost");
        let identity = Identity::new(vec![issued.certificate_pem.into_bytes()], issued.key_pem.into_bytes());
        let response = exchange(identity, vec![issued.certificate_der], version, Port::TCP(0));

        assert!(response.tls, "{version}: a message over TLS must say so");
        assert!(response.secure, "{version}: a message over TLS is a secure one");
        assert!(!response.quic, "{version}: TLS over TCP is not QUIC");
        assert_eq!(response.quic_version, None, "{version}: there is no QUIC version without QUIC");

        assert_eq!(
            response.tls_version.map(|version| version.0),
            Some(TLS_1_3),
            "{version}: the negotiated TLS version must be reported as its wire code",
        );
        assert!(response.tls_cipher.is_some(), "{version}: the negotiated cipher suite must be reported");
        assert!(response.tls_group.is_some(), "{version}: the negotiated named group must be reported");

        assert!(!response.early_data, "{version}: nothing was sent as early data");
    }
}

#[test]
fn a_message_over_quic_carries_the_quic_version_and_the_tls_it_mandates() {
    let issued = issue("localhost");
    let identity = Identity::new(vec![issued.certificate_pem.clone().into_bytes()], issued.key_pem.into_bytes());
    let response = exchange(identity, vec![issued.certificate_pem.into_bytes()], Version::V3_0, Port::QUIC(0));

    assert!(response.quic, "a message over QUIC must say so");
    assert!(response.secure, "QUIC is secure by construction");
    assert_eq!(response.quic_version, Some(quiche::PROTOCOL_VERSION), "the negotiated QUIC version must be reported");

    // RFC 9001 §4.2: QUIC version 1 admits no TLS older than 1.3.
    assert!(response.tls, "QUIC carries TLS within it");
    assert_eq!(response.tls_version.map(|version| version.0), Some(TLS_1_3));
}

#[test]
fn a_message_over_plaintext_carries_nothing_underneath() {
    let server = Server::new(ServerConfig { versions: vec![Version::V1_1], ..ServerConfig::default() });
    let cluster = server.run(Echo, &[Port::TCP(0)], 1).expect("the port did not open");
    let port = cluster.address().expect("the cluster has no address").port();

    let runtime = tokio::runtime::Builder::new_multi_thread().enable_all().build().expect("no runtime");

    let response = runtime.block_on(async move {
        let client = Client::new(ClientConfig { versions: vec![Version::V1_1], secure: false, ..ClientConfig::default() });
        let mut connection = client.connect("127.0.0.1", Port::TCP(port)).await.expect("the client could not reach the server");

        let response = client
            .request(&mut connection, Message::request(Method::GET, "/index.html", Version::V1_1))
            .await
            .expect("the exchange failed");

        connection.close().await;
        response
    });

    cluster.close(Some(1.0));

    assert!(!response.tls, "there is no TLS under a plaintext connection");
    assert!(!response.secure);
    assert!(!response.quic);
    assert_eq!(response.tls_version, None);
    assert_eq!(response.tls_group, None);
    assert_eq!(response.tls_cipher, None);
    assert_eq!(response.quic_version, None);
    assert!(!response.early_data);
}

#[test]
fn a_connection_reports_the_same_facts_it_stamps_on_its_messages() {
    let issued = issue("localhost");
    let identity = Identity::new(vec![issued.certificate_pem.into_bytes()], issued.key_pem.into_bytes());

    let server = Server::new(ServerConfig { versions: vec![Version::V1_1], identity: Some(identity), ..ServerConfig::default() });
    let cluster = server.run(Echo, &[Port::TCP(0)], 1).expect("the port did not open");
    let port = cluster.address().expect("the cluster has no address").port();

    let runtime = tokio::runtime::Builder::new_multi_thread().enable_all().build().expect("no runtime");

    let (security, response) = runtime.block_on(async move {
        let client = Client::new(ClientConfig {
            versions: vec![Version::V1_1],
            roots: Some(vec![issued.certificate_der]),
            ..ClientConfig::default()
        });

        let mut connection = client.connect("localhost", Port::TCP(port)).await.expect("the client could not reach the server");
        let security = connection.security();

        let response = client
            .request(&mut connection, Message::request(Method::GET, "/index.html", Version::V1_1))
            .await
            .expect("the exchange failed");

        connection.close().await;
        (security, response)
    });

    cluster.close(Some(1.0));

    let mut stamped = Message::response(0, Version::V1_1);
    security.apply(&mut stamped);

    assert_eq!(stamped.tls, response.tls);
    assert_eq!(stamped.secure, response.secure);
    assert_eq!(stamped.tls_version, response.tls_version);
    assert_eq!(stamped.tls_group, response.tls_group);
    assert_eq!(stamped.tls_cipher, response.tls_cipher);
    assert_eq!(stamped.quic, response.quic);
    assert_eq!(stamped.quic_version, response.quic_version);
    assert_eq!(stamped.early_data, response.early_data);
}

#[test]
fn a_plaintext_transport_is_what_the_default_security_stands_for() {
    let mut message = Message::response(200, Version::V1_1);
    message.tls = true;
    message.secure = true;
    message.quic = true;

    Security::default().apply(&mut message);

    assert!(!message.tls, "the default stands for nothing underneath, and says so");
    assert!(!message.secure);
    assert!(!message.quic);
}

#[test]
fn a_pkcs12_identity_serves_tls() {
    let archive = base64::decode(BUNDLE_PKCS12).expect("the archive is not Base64");
    let identity = Identity::from_pkcs12(&archive, "secret").expect("the archive did not open");

    let server = Server::new(ServerConfig { versions: vec![Version::V1_1], identity: Some(identity), ..ServerConfig::default() });
    let cluster = server.run(Echo, &[Port::TCP(0)], 1).expect("the port did not open");
    let port = cluster.address().expect("the cluster has no address").port();

    let runtime = tokio::runtime::Builder::new_multi_thread().enable_all().build().expect("no runtime");

    let response = runtime.block_on(async move {
        let client = Client::new(ClientConfig {
            versions: vec![Version::V1_1],
            roots: Some(vec![LEAF.as_bytes().to_vec()]),
            ..ClientConfig::default()
        });

        let transport = tokio::net::TcpStream::connect(("127.0.0.1", port)).await.expect("the port refused a connection");
        let id = ConnectionID(Bytes::from_static(b"test"));

        let mut connection = client
            .connect_stream("soyokaze.test", Box::new(transport), id)
            .await
            .expect("the archived identity did not complete a handshake");

        let request = Message::request(Method::GET, "/index.html", Version::V1_1);
        let response = tokio::time::timeout(std::time::Duration::from_secs(10), client.request(&mut connection, request))
            .await
            .expect("the server did not answer")
            .expect("the exchange failed");

        connection.close().await;
        response
    });

    cluster.close(Some(1.0));

    assert_eq!(response.status_code, Some(200));
    assert_eq!(response.body.as_ref().and_then(Body::inline), Some(Bytes::from_static(b"Hello, World!")));
}
