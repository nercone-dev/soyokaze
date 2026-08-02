use soyokaze::helpers::hpack::HeaderField;

pub const NAMES: &[&str] = &[
    ":method",
    ":path",
    ":scheme",
    ":status",
    ":authority",
    ":protocol",
    "accept",
    "accept-encoding",
    "authorization",
    "cache-control",
    "content-length",
    "content-type",
    "cookie",
    "date",
    "server",
    "set-cookie",
    "user-agent",
    "vary",
    "x-soyokaze",
];

pub const VALUES: &[&str] = &[
    "",
    "*/*",
    "/",
    "/index.html",
    "0",
    "200",
    "404",
    "GET",
    "POST",
    "Soyokaze",
    "gzip, deflate",
    "https",
    "max-age=0",
    "no-cache",
    "text/html; charset=utf-8",
    "trailers",
];

pub struct Input<'a> {
    data: &'a [u8],
    offset: usize,
}

impl<'a> Input<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self { data, offset: 0 }
    }

    pub fn byte(&mut self) -> u8 {
        match self.data.get(self.offset) {
            Some(byte) => {
                self.offset += 1;
                *byte
            }
            None => 0,
        }
    }

    pub fn below(&mut self, bound: usize) -> usize {
        if bound == 0 { 0 } else { self.byte() as usize % bound }
    }

    pub fn take(&mut self, count: usize) -> &'a [u8] {
        let data = self.data;
        let end = self.offset.saturating_add(count).min(data.len());
        let slice = &data[self.offset..end];
        self.offset = end;
        slice
    }

    pub fn text(&mut self, max: usize) -> String {
        let count = self.below(max + 1);
        String::from_utf8_lossy(self.take(count)).into_owned()
    }

    pub fn name(&mut self, max: usize) -> String {
        match self.byte() % 3 {
            0 => NAMES[self.below(NAMES.len())].to_owned(),
            _ => self.text(max),
        }
    }

    pub fn value(&mut self, max: usize) -> String {
        match self.byte() % 3 {
            0 => VALUES[self.below(VALUES.len())].to_owned(),
            _ => self.text(max),
        }
    }

    pub fn field(&mut self, max: usize) -> HeaderField {
        HeaderField::new(self.name(max), self.value(max))
    }

    pub fn fields(&mut self, max_fields: usize, max_octets: usize) -> Vec<HeaderField> {
        let count = self.below(max_fields + 1);
        (0..count).map(|_| self.field(max_octets)).collect()
    }

    pub fn sections(&mut self, max_sections: usize, max_fields: usize, max_octets: usize) -> Vec<Vec<HeaderField>> {
        let count = self.below(max_sections) + 1;
        (0..count).map(|_| self.fields(max_fields, max_octets)).collect()
    }
}
