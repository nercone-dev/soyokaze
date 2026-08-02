use soyokaze::helpers::scan;
use soyokaze::protocol::h1;

pub fn check(data: &[u8]) {
    classifier(data);
    field_line(data);
    header_block(data);
}

pub fn classifier(data: &[u8]) {
    let control = data.iter().any(|octet| (*octet < 0x20 && *octet != b'\t') || *octet == 0x7f);
    let obs_text = data.iter().any(|octet| *octet >= 0x80);
    let expected = (control as u8) | (obs_text as u8) << 1;

    assert_eq!(scan::classify_field_value(data), expected, "the classifier disagreed on {data:?}");
    assert_eq!(scan::is_field_value(data), !control, "is_field_value disagreed on {data:?}");

    for skip in 1..data.len().min(9) {
        let tail = &data[skip..];
        let control = tail.iter().any(|octet| (*octet < 0x20 && *octet != b'\t') || *octet == 0x7f);
        let obs_text = tail.iter().any(|octet| *octet >= 0x80);

        assert_eq!(
            scan::classify_field_value(tail),
            (control as u8) | (obs_text as u8) << 1,
            "the classifier disagreed on {tail:?}",
        );
    }
}

pub fn field_line(data: &[u8]) {
    let Ok((name, value)) = h1::parse_field(data) else {
        return;
    };

    assert!(!name.is_empty(), "an empty field name parsed out of {data:?}");
    assert!(h1::is_token(&name), "field name {name:?} is not a token");
    assert!(!name.bytes().any(|byte| byte.is_ascii_uppercase()), "field name {name:?} was not lowercased");
    assert!(h1::is_field_value(value.as_bytes()), "field value {value:?} carries a control character");

    let line = h1::write_header_line(&name, &value, soyokaze::HeaderCase::Lower)
        .expect("a parsed field line did not write back out");

    let written = line.strip_suffix("\r\n").expect("a written field line is not CRLF terminated");
    let (again, value_again) = h1::parse_field(written.as_bytes()).expect("a written field line did not parse back");

    assert_eq!(again, name, "a round trip changed the field name");
    assert_eq!(value_again, value, "a round trip changed the field value");
}

pub fn header_block(data: &[u8]) {
    let Ok(headers) = h1::parse_header_block(data, 100) else {
        return;
    };

    let lines = data.split(|octet| *octet == b'\n').filter(|line| !line.is_empty());
    let parsed: Vec<_> = lines
        .map(|line| h1::parse_field(&line[..line.len() - 1]).expect("a line of an accepted block did not parse"))
        .collect();

    assert_eq!(headers.len(), parsed.len(), "the block and its lines disagreed on how many fields there are");

    for ((name, value), (line_name, line_value)) in headers.iter().zip(&parsed) {
        assert_eq!(name, line_name.as_str(), "the block and its lines disagreed on a field name");
        assert_eq!(value, line_value.as_str(), "the block and its lines disagreed on a field value");
    }
}
