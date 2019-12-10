use std::ops::Deref;

pub fn to_hex_string(bytes: &[u8]) -> String {
    let mut s = String::new();
    write_hex_bytes(&mut s, bytes);
    s
}

pub fn write_hex_bytes<W>(w: &mut W, bytes: &[u8]) where W: std::fmt::Write {
    for byte in bytes {
        write!(w, "{:02x}", byte).unwrap();
    }
}

pub fn write_output(s: &str) {
    println!("{}", s);
}


//TODO remove this when feature 'inner_deref' becomes stable
pub trait OptionDeref<T: Deref> {
    fn derefed(&self) -> Option<&T::Target>;
}

impl<T: Deref> OptionDeref<T> for Option<T> {
    fn derefed(&self) -> Option<&T::Target> {
        self.as_ref().map(Deref::deref)
    }
}