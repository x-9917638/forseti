use std::io::{self, Read, Write};

pub fn write_u8<W: Write>(w: &mut W, v: u8) -> io::Result<()> {
    w.write_all(&[v])
}

pub fn write_u32<W: Write>(w: &mut W, v: u32) -> io::Result<()> {
    w.write_all(&v.to_le_bytes())
}

pub fn write_u64<W: Write>(w: &mut W, v: u64) -> io::Result<()> {
    w.write_all(&v.to_le_bytes())
}

pub fn write_bytes<W: Write>(w: &mut W, bytes: &[u8]) -> io::Result<()> {
    write_u64(w, bytes.len() as u64)?;
    w.write_all(bytes)
}

pub fn write_string<W: Write>(w: &mut W, s: &str) -> io::Result<()> {
    write_bytes(w, s.as_bytes())
}

pub fn write_key_value<W: Write>(w: &mut W, k: &str, v: &[u8]) -> io::Result<()> {
    write_string(w, k)?;
    write_bytes(w, v)
}

pub fn read_u8<R: Read>(r: &mut R) -> io::Result<u8> {
    let mut buf = [0u8; 1];
    r.read_exact(&mut buf)?;
    Ok(buf[0])
}

pub fn read_u32<R: Read>(r: &mut R) -> io::Result<u32> {
    let mut buf = [0u8; 4];
    r.read_exact(&mut buf)?;
    Ok(u32::from_le_bytes(buf))
}

pub fn read_u64<R: Read>(r: &mut R) -> io::Result<u64> {
    let mut buf = [0u8; 8];
    r.read_exact(&mut buf)?;
    Ok(u64::from_le_bytes(buf))
}

pub fn read_bytes<R: Read>(r: &mut R) -> io::Result<Vec<u8>> {
    let len = read_u64(r)? as usize;
    let mut buf = vec![0u8; len];
    r.read_exact(&mut buf)?;
    Ok(buf)
}

pub fn read_string<R: Read>(r: &mut R) -> io::Result<String> {
    let bytes = read_bytes(r)?;
    String::from_utf8(bytes).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

pub fn read_key_value<R: Read>(r: &mut R) -> io::Result<(String, Vec<u8>)> {
    Ok((read_string(r)?, read_bytes(r)?))
}
