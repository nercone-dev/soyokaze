use soyokaze::helpers::huffman;

pub fn check(data: &[u8]) {
    decode(data);
    roundtrip(data);
}

pub fn decode(data: &[u8]) {
    let Ok(decoded) = huffman::decode(data) else {
        return;
    };

    let reencoded = huffman::encode(&decoded);
    assert_eq!(
        reencoded.len(),
        huffman::encoded_len(&decoded),
        "encoded_len disagreed with encode for {decoded:?}",
    );

    assert_eq!(
        huffman::decode(&reencoded).as_deref(),
        Ok(&decoded[..]),
        "re-encoding a decoded string did not decode back to it",
    );
}

pub fn roundtrip(data: &[u8]) {
    let encoded = huffman::encode(data);

    assert_eq!(encoded.len(), huffman::encoded_len(data), "encoded_len disagreed with encode");
    assert_eq!(huffman::decode(&encoded).as_deref(), Ok(data), "a round trip changed the string");
}
