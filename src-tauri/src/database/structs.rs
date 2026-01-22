// During development of the lib
#![allow(unused)]

use super::helpers::*;
use aes_gcm::{
    Aes256Gcm, Nonce as AesNonce,
    aead::{Aead, KeyInit},
};
use argon2::{self, Algorithm, Argon2, Version};
use blake3;
use chacha20poly1305::{ChaCha20Poly1305, Nonce as ChaNonce};
use flate2::{Compression, write::GzEncoder};
use lz4_flex::frame::FrameEncoder;
use rand::{Rng, TryRngCore, rng, rngs::OsRng};
use std::{
    env,
    fs::{File, rename},
    io::{self, Read, Write},
};
use time::{self, OffsetDateTime};

trait RegenerateNonces {
    /// This function should regenerate all nonces in the struct.
    ///
    /// Regenerate nonces of the struct in place, and if needed,
    /// call regenerate() on child structs too.
    fn regenerate(&mut self);
}

trait Serialise: Sized {
    fn serialise<W: Write>(&self, w: &mut W) -> io::Result<()>;
    fn deserialise<R: Read>(r: &mut R) -> io::Result<Self>;
}

/// A struct representing the entire file of a database.
///
/// The order of fields here matches the order of data written to disk
///
/// # Disk layout:
///
/// header
///
/// header_hash
///
/// internal_content_hash
///
/// internal_content (encrypted, optionally compressed)
pub struct DatabaseFile {
    header: Header,
    /// 256-bit blake3 keyed hash of the outer header
    ///
    /// This should always be zeroed during runtime, it is here for clarity.
    header_hash: [u8; 32],
    /// 256-bit blake3 keyed hash of the (optionally) compressed, encrypted internal contents.
    ///
    /// This should always be zeroed during runtime, it is here for clarity.
    internal_content_hash: [u8; 32],
    internal_content: InternalContent,
}

impl RegenerateNonces for DatabaseFile {
    /// Regenerates salts and nonces and clears hashes.
    ///
    /// NOTE: This does not regenerate any hashes. Hashes
    /// must be recalculated using serialise()
    fn regenerate(&mut self) {
        self.header.regenerate();
        self.header_hash = [0u8; 32];
        self.internal_content_hash = [0u8; 32];
    }
}

impl DatabaseFile {
    /// Create a new DatabaseFile struct.
    pub fn new(header: Header, internal_content: InternalContent) -> Self {
        Self {
            header,
            header_hash: [0u8; 32],
            internal_content_hash: [0u8; 32],
            internal_content,
        }
    }

    /// Given a path to read from, deserialise a file
    /// into a DatabaseFile. This method decrypts the internal contents
    /// and zeroises the 2 hashes.
    fn deserialise(path: &str, master_password: &[u8]) -> Result<Self, io::Error> {
        let mut dbfile = File::open(path)?;
        let mut header_buf = [0u8; HEADER_SIZE];
        dbfile.read_exact(&mut header_buf)?;

        let mut file_header_hash = [0u8; 32];
        dbfile.read_exact(&mut file_header_hash)?;
        let header = Header::deserialise(&mut header_buf.clone().as_slice())?;

        // Integrity checks
        let derived_key =
            DatabaseFile::generate_key(&header.fields.key_derivation_params, master_password)
                .map_err(|e| io::Error::other(format!("key derivation failed: {e}")))?;

        let file_header_hash = blake3::Hash::from_bytes(file_header_hash);
        let new_hash = blake3::keyed_hash(&derived_key, &header_buf);

        if file_header_hash != new_hash {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "Invalid password or corrupted file header!",
            ));
        }

        let mut file_internal_hash = [0u8; 32];
        dbfile.read_exact(&mut file_internal_hash)?;
        let file_internal_hash = blake3::Hash::from_bytes(file_internal_hash);

        let mut internal_ciphertext = Vec::new();
        dbfile.read_to_end(&mut internal_ciphertext)?;
        let new_internal_hash = blake3::keyed_hash(&derived_key, &internal_ciphertext);
        // Integrity checks
        if file_internal_hash != new_internal_hash {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "Invalid password or corrupted file contents!",
            ));
        }

        // Decrypt
        let internal_content_buf = DatabaseFile::decrypt(
            &header.fields.encryption,
            &header.fields.init_vector,
            &derived_key,
            internal_ciphertext,
        )?;

        let internal_content = match header.fields.compression {
            CompressionAlgorithm::None => internal_content_buf,
            CompressionAlgorithm::Lz4 => {
                let mut decoder = lz4_flex::frame::FrameDecoder::new(&internal_content_buf[..]);
                let mut out = Vec::new();
                std::io::copy(&mut decoder, &mut out)?;
                out
            }
            CompressionAlgorithm::GZip => {
                let mut decoder = flate2::read::GzDecoder::new(&internal_content_buf[..]);
                let mut out = Vec::new();
                std::io::copy(&mut decoder, &mut out)?;
                out
            }
        };

        let internal_content = InternalContent::deserialise(&mut internal_content.as_slice())?;

        Ok(Self {
            header,
            header_hash: [0u8; 32],
            internal_content_hash: [0u8; 32],
            internal_content,
        })
    }

    fn save(
        &mut self,
        path: &str,
        method: SaveMethod,
        master_password: &[u8],
    ) -> Result<(), io::Error> {
        // Regenerate all needed nonces / salts
        self.regenerate();

        match method {
            SaveMethod::Atomic => {
                let tmp_path = self.serialise_to_tmp(master_password)?;
                // Move tmpfile to correct path
                // This MUST be on the same filesystem.
                rename(tmp_path, path)?;
                Ok(())
            }
            SaveMethod::Direct => {
                // Open and write to file directly
                let mut file = File::create(path)?;
                self.serialise(&mut file, master_password)
            }
        }
    }

    /// Serialises db to a temporary file with a random name,
    /// returning the filepath of that file.
    fn serialise_to_tmp(&self, master_password: &[u8]) -> Result<std::path::PathBuf, io::Error> {
        let random_filename: String = rng()
            .sample_iter(&rand::distr::Alphanumeric)
            .take(24)
            .map(char::from)
            .collect::<String>()
            + "-"
            + &time::UtcDateTime::now().to_string()
            + ".tfedb";
        let tmp_path = env::temp_dir().join(random_filename);
        let mut file_buf: File = File::create(&tmp_path)?;
        self.serialise(&mut file_buf, master_password)?;
        Ok(tmp_path)
    }

    fn serialise<W: Write>(&self, w: &mut W, master_password: &[u8]) -> io::Result<()> {
        let mut header_buf = Vec::new();
        self.header.serialise(&mut header_buf)?;

        let derived_key =
            DatabaseFile::generate_key(&self.header.fields.key_derivation_params, master_password)
                .map_err(|e| io::Error::other(format!("key derivation failed: {e}")))?;

        let header_mac = blake3::keyed_hash(&derived_key, &header_buf);
        w.write_all(&header_buf)?;
        w.write_all(header_mac.as_bytes())?;

        let mut internal_buffer = Vec::new();
        self.serialise_internal(&mut internal_buffer)?;

        let ciphertext = DatabaseFile::encrypt(
            &self.header.fields.encryption,
            &self.header.fields.init_vector,
            &derived_key,
            internal_buffer,
        )?;

        let internal_mac = blake3::keyed_hash(&derived_key, &ciphertext);

        w.write_all(internal_mac.as_bytes())?;
        w.write_all(&ciphertext)?;

        Ok(())
    }

    fn encrypt(
        encryption: &EncryptionAlgorithm,
        init_vector: &[u8; 12],
        derived_key: &[u8; 32],
        internal_buffer: Vec<u8>,
    ) -> Result<Vec<u8>, io::Error> {
        let ciphertext = match encryption {
            EncryptionAlgorithm::Aes => {
                let cipher = Aes256Gcm::new_from_slice(derived_key)
                    .map_err(|_| io::Error::other("AES-GCM key init failed"))?;
                let nonce = AesNonce::from_slice(init_vector);
                cipher
                    .encrypt(nonce, internal_buffer.as_ref())
                    .map_err(|_| io::Error::other("AES-GCM encryption failed"))?
            }
            EncryptionAlgorithm::ChaCha20 => {
                let cipher = ChaCha20Poly1305::new_from_slice(derived_key)
                    .map_err(|_| io::Error::other("ChaCha20-Poly1305 key init failed"))?;
                let nonce = ChaNonce::from_slice(init_vector);
                cipher
                    .encrypt(nonce, internal_buffer.as_ref())
                    .map_err(|_| io::Error::other("ChaCha20-Poly1305 encryption failed"))?
            }
        };
        Ok(ciphertext)
    }

    fn decrypt(
        encryption: &EncryptionAlgorithm,
        init_vector: &[u8; 12],
        derived_key: &[u8; 32],
        ciphertext: Vec<u8>,
    ) -> Result<Vec<u8>, io::Error> {
        let plaintext = match encryption {
            EncryptionAlgorithm::Aes => {
                let cipher = Aes256Gcm::new_from_slice(derived_key)
                    .map_err(|_| io::Error::other("AES-GCM key init failed"))?;
                let nonce = AesNonce::from_slice(init_vector);
                cipher
                    .decrypt(nonce, ciphertext.as_ref())
                    .map_err(|_| io::Error::other("AES-GCM encryption failed"))?
            }
            EncryptionAlgorithm::ChaCha20 => {
                let cipher = ChaCha20Poly1305::new_from_slice(derived_key)
                    .map_err(|_| io::Error::other("ChaCha20-Poly1305 key init failed"))?;
                let nonce = ChaNonce::from_slice(init_vector);
                cipher
                    .decrypt(nonce, ciphertext.as_ref())
                    .map_err(|_| io::Error::other("ChaCha20-Poly1305 encryption failed"))?
            }
        };
        Ok(plaintext)
    }

    fn serialise_internal<W: Write>(&self, w: &mut W) -> io::Result<()> {
        // Write the internal contents to a new buffer
        match self.header.fields.compression {
            CompressionAlgorithm::None => {
                self.internal_content.serialise(w)?;
            }
            CompressionAlgorithm::Lz4 => {
                let mut buffer = FrameEncoder::new(w);
                self.internal_content.serialise(&mut buffer)?;
                buffer.try_finish()?;
            }
            CompressionAlgorithm::GZip => {
                let mut buffer = GzEncoder::new(w, Compression::default());
                self.internal_content.serialise(&mut buffer)?;
                buffer.try_finish()?;
            }
        };
        Ok(())
    }

    fn generate_key(params: &KDFParams, password: &[u8]) -> Result<[u8; 32], argon2::Error> {
        let mut output = [0u8; 32];
        let version = Version::V0x13;
        let argon2_params = argon2::Params::new(
            params.memory,
            params.iterations,
            params.threads,
            Some(32usize),
        )?;
        let kdf = match params.variant {
            KeyDerivationFunction::Argon2d => {
                Argon2::new(Algorithm::Argon2d, version, argon2_params)
            }
            KeyDerivationFunction::Argon2id => {
                Argon2::new(Algorithm::Argon2id, version, argon2_params)
            }
        };
        kdf.hash_password_into(password, &params.salt, &mut output)?;
        Ok(output)
    }
}

pub enum SaveMethod {
    // Tempfile
    Atomic = 0,
    Direct = 1,
}

/// The header of the database.
pub struct Header {
    sig_1: u32, // 0x1c2f4ee6
    sig_2: u32, // 0xb224e656
    fields: HeaderFields,
}
/// Size of Header struct in bytes (u8)
const HEADER_SIZE: usize = 4 + 4 + HEADER_FIELDS_SIZE;

impl Header {
    pub fn new(fields: HeaderFields) -> Self {
        Header {
            sig_1: 0x1c2f4ee6,
            sig_2: 0xb224e656,
            fields,
        }
    }
}

impl RegenerateNonces for Header {
    fn regenerate(&mut self) {
        self.fields.regenerate();
    }
}

impl Serialise for Header {
    fn serialise<W: Write>(&self, w: &mut W) -> io::Result<()> {
        write_u32(w, self.sig_1)?;
        write_u32(w, self.sig_2)?;
        self.fields.serialise(w)?;
        Ok(())
    }

    fn deserialise<R: Read>(r: &mut R) -> io::Result<Self> {
        let sig_1 = read_u32(r)?;
        let sig_2 = read_u32(r)?;
        let fields = HeaderFields::deserialise(r)?;

        Ok(Self {
            sig_1,
            sig_2,
            fields,
        })
    }
}

/// Size of HeaderFields struct in bytes (u8)
const HEADER_FIELDS_SIZE: usize = 1 + 1 + 32 + 12 + KDF_PARAMS_SIZE;

pub struct HeaderFields {
    /// The encryption algorithm to use.
    /// Defaults to AES-256
    encryption: EncryptionAlgorithm,
    /// The compression algorithm to use.
    /// Defaults to LZ4
    compression: CompressionAlgorithm,
    /// The salt used.
    /// Should be regenerated on database save.
    salt: [u8; 32],
    /// The nonce used as an initialisation vector.
    /// Should be regenerated on database save.
    init_vector: [u8; 12],
    /// The paramaters for the key derivation function.
    /// Forseti only supports Argon2, variants Argon2d and Argon2id.
    key_derivation_params: KDFParams,
}

impl HeaderFields {
    /// Create a new HeaderFields struct. Note that salt and nonce are zeroed.
    pub fn new(
        encryption: Option<EncryptionAlgorithm>,
        compression: Option<CompressionAlgorithm>,
        key_derivation_params: KDFParams,
    ) -> Self {
        Self {
            encryption: encryption.unwrap_or(EncryptionAlgorithm::Aes),
            compression: compression.unwrap_or(CompressionAlgorithm::Lz4),
            salt: [0u8; 32],
            init_vector: [0u8; 12],
            key_derivation_params,
        }
    }
    fn make_hash(&self) {
        todo!()
    }
}

impl RegenerateNonces for HeaderFields {
    fn regenerate(&mut self) {
        OsRng
            .try_fill_bytes(&mut self.salt)
            .expect("Failed to regenerate salt [HeaderFields]");
        OsRng
            .try_fill_bytes(&mut self.init_vector)
            .expect("Failed to regenerate initialisation vector [HeaderFields]");
        self.key_derivation_params.regenerate();
    }
}

impl Serialise for HeaderFields {
    fn serialise<W: Write>(&self, w: &mut W) -> io::Result<()> {
        // Header fields
        write_u8(w, self.encryption.to_u8())?;
        write_u8(w, self.compression.to_u8())?;

        w.write_all(&self.salt)?;
        w.write_all(&self.init_vector)?;

        self.key_derivation_params.serialise(w)?;

        Ok(())
    }

    fn deserialise<R: Read>(r: &mut R) -> io::Result<Self> {
        let encryption = EncryptionAlgorithm::try_from_u8(read_u8(r)?)?;
        let compression = CompressionAlgorithm::try_from_u8(read_u8(r)?)?;

        let mut salt = [0u8; 32];
        r.read_exact(&mut salt)?;
        let mut init_vector = [0u8; 12];
        r.read_exact(&mut init_vector)?;

        let key_derivation_params = KDFParams::deserialise(r)?;

        Ok(Self {
            encryption,
            compression,
            salt,
            init_vector,
            key_derivation_params,
        })
    }
}

pub enum EncryptionAlgorithm {
    // All are 256-bit
    Aes = 0,
    ChaCha20 = 1,
}

impl EncryptionAlgorithm {
    fn to_u8(&self) -> u8 {
        match self {
            Self::Aes => 0,
            Self::ChaCha20 => 1,
        }
    }
    fn from_u8(i: u8) -> Self {
        match i {
            0 => Self::Aes,
            1 => Self::ChaCha20,
            _ => unreachable!("Invalid value for encryption algorithm"),
        }
    }
    fn try_from_u8(i: u8) -> Result<Self, io::Error> {
        match i {
            0 => Ok(Self::Aes),
            1 => Ok(Self::ChaCha20),
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Invalid value for encryption algorithm",
            )),
        }
    }
}

pub enum CompressionAlgorithm {
    None = 0,
    Lz4 = 1,
    GZip = 2,
}

impl CompressionAlgorithm {
    fn to_u8(&self) -> u8 {
        match self {
            Self::None => 0,
            Self::Lz4 => 1,
            Self::GZip => 2,
        }
    }
    fn from_u8(i: u8) -> Self {
        match i {
            0 => Self::None,
            1 => Self::Lz4,
            2 => Self::GZip,
            _ => unreachable!("Invalid value for compression algorithm"),
        }
    }
    fn try_from_u8(i: u8) -> Result<Self, io::Error> {
        match i {
            0 => Ok(Self::None),
            1 => Ok(Self::Lz4),
            2 => Ok(Self::GZip),
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Invalid value for compression algorithm",
            )),
        }
    }
}

/// Size of KDFParams struct in bytes (u8)
const KDF_PARAMS_SIZE: usize = 1 + 32 + 4 + 4 + 4;
/// Struct containing the parameters that should be passed to the key derivation function
pub struct KDFParams {
    /// Which vairant of Argon2 to use.
    ///
    /// Defaults to Argon2d
    variant: KeyDerivationFunction,
    /// The salt used.
    /// Should be regenerated on database save.
    salt: [u8; 32],
    /// Iterations to use.
    /// Minimum 1.
    iterations: u32,
    /// Memory, in kilobytes (1024 bytes).
    /// Minimum 8.
    memory: u32,
    /// Number of threads to use.
    /// Minimum 1.
    threads: u32,
}

impl KDFParams {
    pub fn new(
        variant: Option<KeyDerivationFunction>,
        iterations: u32,
        memory: u32,
        threads: u32,
    ) -> Self {
        let mut salt = [0u8; 32];
        OsRng
            .try_fill_bytes(&mut salt)
            .expect("Failed to generate a salt");
        Self {
            variant: variant.unwrap_or(KeyDerivationFunction::Argon2d),
            salt,
            iterations,
            memory,
            threads,
        }
    }
}

impl RegenerateNonces for KDFParams {
    fn regenerate(&mut self) {
        OsRng
            .try_fill_bytes(&mut self.salt)
            .expect("Failed to regenerate salt [KDFParams]");
    }
}

impl Serialise for KDFParams {
    fn serialise<W: Write>(&self, w: &mut W) -> io::Result<()> {
        write_u8(w, self.variant.to_u8())?;
        w.write_all(&self.salt)?;
        write_u32(w, self.iterations)?;
        write_u32(w, self.memory)?;
        write_u32(w, self.threads)?;
        Ok(())
    }

    fn deserialise<R: Read>(r: &mut R) -> io::Result<Self> {
        let variant = KeyDerivationFunction::try_from_u8(read_u8(r)?)?;
        let mut salt = [0u8; 32];
        r.read_exact(&mut salt)?;
        let iterations = read_u32(r)?;
        let memory = read_u32(r)?;
        let threads = read_u32(r)?;

        Ok(Self {
            variant,
            salt,
            iterations,
            memory,
            threads,
        })
    }
}

pub enum KeyDerivationFunction {
    Argon2d = 0,
    Argon2id = 1,
}

impl KeyDerivationFunction {
    fn to_u8(&self) -> u8 {
        match self {
            Self::Argon2d => 0,
            Self::Argon2id => 1,
        }
    }
    fn from_u8(i: u8) -> Self {
        match i {
            0 => Self::Argon2d,
            1 => Self::Argon2id,
            _ => unreachable!("Invalid value for key derivation function"),
        }
    }
    fn try_from_u8(i: u8) -> Result<Self, io::Error> {
        match i {
            0 => Ok(Self::Argon2d),
            1 => Ok(Self::Argon2id),
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Invalid value for key derivation function",
            )),
        }
    }
}

pub struct Entry {
    /// An svg icon.
    ///
    /// An empty string represents no icon.
    icon: String,
    username: String,
    password: Vec<u8>,
    url: String,
    /// The date and time of password expiry, in local timezone.
    expiry: Option<time::OffsetDateTime>,
    /// Any extra notes that the user records.
    notes: String,
}

impl Serialise for Entry {
    fn serialise<W: Write>(&self, w: &mut W) -> io::Result<()> {
        write_string(w, &self.icon)?;
        write_string(w, &self.username)?;
        write_bytes(w, &self.password)?; // or Vec<u8>
        write_string(w, &self.url)?;

        match &self.expiry {
            Some(dt) => {
                write_u8(w, 1)?;
                dt.serialise(w)?;
            }
            None => {
                write_u8(w, 0)?;
            }
        }

        write_string(w, &self.notes)?;
        Ok(())
    }

    fn deserialise<R: Read>(r: &mut R) -> io::Result<Self> {
        let icon = read_string(r)?;
        let username = read_string(r)?;
        let password = read_bytes(r)?;
        let url = read_string(r)?;

        // A 0 indicates no expiry set.
        let expiry = if read_u8(r)? == 1 {
            Some(OffsetDateTime::deserialise(r)?)
        } else {
            None
        };
        let notes = read_string(r)?;

        Ok(Self {
            icon,
            username,
            password,
            url,
            expiry,
            notes,
        })
    }
}

impl Serialise for time::OffsetDateTime {
    fn serialise<W: Write>(&self, w: &mut W) -> io::Result<()> {
        let unix = self.unix_timestamp();
        let offset = self.offset().whole_seconds();

        w.write_all(&unix.to_le_bytes())?;
        w.write_all(&(offset).to_le_bytes())?;
        Ok(())
    }

    fn deserialise<R: Read>(r: &mut R) -> io::Result<Self> {
        // Read unix timestamp (i64)
        let mut unix_buf = [0u8; 8];
        r.read_exact(&mut unix_buf)?;
        let unix = i64::from_le_bytes(unix_buf);

        // Read offset seconds (i32)
        let mut offset_buf = [0u8; 4];
        r.read_exact(&mut offset_buf)?;
        let offset_secs = i32::from_le_bytes(offset_buf);

        let dt = time::OffsetDateTime::from_unix_timestamp(unix).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid unix timestamp: {e}"),
            )
        })?;

        let utc_offset = time::UtcOffset::from_whole_seconds(offset_secs).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid utc offset: {e}"),
            )
        })?;

        Ok(dt.to_offset(utc_offset))
    }
}

pub struct InternalContent {
    entries: Vec<Entry>,
    /// A list of files associated with each entry.
    /// Each entry may have 0-18446744073709551615 files associated
    /// with it.
    ///
    /// Files are stored as an array of bytes. This is
    /// intended to be used for small files, e.g. a keyfile or similar.
    ///
    /// Note that files.len() must always eq entries.len()
    files: Vec<Vec<Vec<u8>>>,
}

impl Serialise for InternalContent {
    fn serialise<W: Write>(&self, w: &mut W) -> io::Result<()> {
        // Enforce invariant before serialisation
        if self.files.len() != self.entries.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "files and entries length mismatch",
            ));
        }

        // Writing lengths allows for preallocating vectors during deserialisation.
        write_u64(w, self.entries.len() as u64)?;
        write_u64(w, self.files.len() as u64)?;

        for entry in &self.entries {
            entry.serialise(w)?;
        }

        for entry_files in &self.files {
            write_u64(w, entry_files.len() as u64)?;
            for file in entry_files {
                write_bytes(w, file)?;
            }
        }

        Ok(())
    }

    fn deserialise<R: Read>(r: &mut R) -> io::Result<Self> {
        let num_entries = read_u64(r)?;
        let num_files = read_u64(r)?;

        if num_files != num_entries {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Integrity check fail: number of entries != number of file stores!",
            ));
        }

        let mut entries = Vec::with_capacity(num_entries as usize);
        for _ in 0..num_entries {
            entries.push(Entry::deserialise(r)?);
        }

        let mut files = Vec::with_capacity(num_files as usize);
        for _ in 0..num_files {
            let num_entry_files = read_u64(r)?;
            let mut entry_files = Vec::with_capacity(num_entry_files as usize);
            for _ in 0..num_entry_files {
                entry_files.push(read_bytes(r)?);
            }
            files.push(entry_files);
        }

        Ok(Self { entries, files })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::{Duration, OffsetDateTime, UtcOffset};

    fn sample_kdf() -> KDFParams {
        KDFParams {
            variant: KeyDerivationFunction::Argon2id,
            salt: [1u8; 32],
            iterations: 1,
            memory: 8,
            threads: 1,
        }
    }

    fn sample_header_fields(enc: EncryptionAlgorithm, comp: CompressionAlgorithm) -> HeaderFields {
        HeaderFields {
            encryption: enc,
            compression: comp,
            salt: [2u8; 32],
            init_vector: [3u8; 12],
            key_derivation_params: sample_kdf(),
        }
    }

    fn sample_entry() -> Entry {
        let now = OffsetDateTime::now_utc().to_offset(UtcOffset::from_whole_seconds(3600).unwrap());
        Entry {
            icon: "<svg/>".to_string(),
            username: "user".to_string(),
            password: b"pass123".to_vec(),
            url: "https://example.com".to_string(),
            expiry: Some(now + Duration::days(10)),
            notes: "note".to_string(),
        }
    }

    fn sample_db(enc: EncryptionAlgorithm, comp: CompressionAlgorithm) -> DatabaseFile {
        let fields = sample_header_fields(enc, comp);
        let header = Header::new(fields);
        let ic = InternalContent {
            entries: vec![sample_entry(), sample_entry()],
            files: vec![Vec::new(), vec![b"file1".to_vec()]],
        };
        DatabaseFile::new(header, ic)
    }

    #[test]
    fn header_fields_serialisation_roundtrip() {
        let fields = sample_header_fields(EncryptionAlgorithm::Aes, CompressionAlgorithm::Lz4);
        let mut buf = Vec::new();
        fields.serialise(&mut buf).unwrap();

        let parsed = HeaderFields::deserialise(&mut buf.as_slice()).unwrap();

        assert_eq!(parsed.encryption.to_u8(), fields.encryption.to_u8());
        assert_eq!(parsed.compression.to_u8(), fields.compression.to_u8());
        assert_eq!(parsed.salt, fields.salt);
        assert_eq!(parsed.init_vector, fields.init_vector);

        // KDF params equality
        let p = &parsed.key_derivation_params;
        let f = &fields.key_derivation_params;
        assert_eq!(p.variant.to_u8(), f.variant.to_u8());
        assert_eq!(p.salt, f.salt);
        assert_eq!(p.iterations, f.iterations);
        assert_eq!(p.memory, f.memory);
        assert_eq!(p.threads, f.threads);
    }

    #[test]
    fn kdf_params_serialisation_roundtrip() {
        let params = sample_kdf();
        let mut buf = Vec::new();
        params.serialise(&mut buf).unwrap();

        let parsed = KDFParams::deserialise(&mut buf.as_slice()).unwrap();

        assert_eq!(parsed.variant.to_u8(), params.variant.to_u8());
        assert_eq!(parsed.salt, params.salt);
        assert_eq!(parsed.iterations, params.iterations);
        assert_eq!(parsed.memory, params.memory);
        assert_eq!(parsed.threads, params.threads);
    }

    #[test]
    fn entry_and_time_roundtrip() {
        let entry = sample_entry();

        let mut buf = Vec::new();
        entry.serialise(&mut buf).unwrap();

        let parsed = Entry::deserialise(&mut buf.as_slice()).unwrap();

        assert_eq!(parsed.icon, entry.icon);
        assert_eq!(parsed.username, entry.username);
        assert_eq!(parsed.password, entry.password);
        assert_eq!(parsed.url, entry.url);
        assert_eq!(parsed.notes, entry.notes);

        match (parsed.expiry, entry.expiry) {
            (Some(a), Some(b)) => {
                assert_eq!(a.unix_timestamp(), b.unix_timestamp());
                assert_eq!(a.offset().whole_seconds(), b.offset().whole_seconds());
            }
            (None, None) => {}
            _ => panic!("expiry mismatch"),
        }
    }

    #[test]
    fn internal_content_invariant_mismatch_errors() {
        // files.len() != entries.len() should error
        let ic = InternalContent {
            entries: vec![sample_entry()],
            files: vec![], // mismatch
        };
        let mut buf = Vec::new();
        let err = ic.serialise(&mut buf).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
    }

    #[test]
    fn database_aes_gcm_serialise_deserialise() {
        let db = sample_db(EncryptionAlgorithm::Aes, CompressionAlgorithm::None);

        let master = b"master_password";

        // Write to buffer
        let mut buf = Vec::new();
        db.serialise(&mut buf, master).unwrap();

        // Read back via file-like API using a temp file path
        // Use deserialise(path, master)
        // Since deserialise expects a path, write to a tempfile.
        let tmp = std::env::temp_dir().join("forseti_test_aes_gcm.tfedb");
        std::fs::write(&tmp, &buf).unwrap();

        let loaded = DatabaseFile::deserialise(tmp.to_str().unwrap(), master).unwrap();

        // Basic structural checks
        assert_eq!(
            loaded.header.fields.encryption.to_u8(),
            db.header.fields.encryption.to_u8()
        );
        assert_eq!(
            loaded.header.fields.compression.to_u8(),
            db.header.fields.compression.to_u8()
        );
        assert_eq!(
            loaded.internal_content.entries.len(),
            db.internal_content.entries.len()
        );
        assert_eq!(
            loaded.internal_content.files.len(),
            db.internal_content.files.len()
        );
    }

    #[test]
    fn database_chacha20_serialise_deserialise() {
        let db = sample_db(EncryptionAlgorithm::ChaCha20, CompressionAlgorithm::Lz4);

        let master = b"master_password_2";

        let mut buf = Vec::new();
        db.serialise(&mut buf, master).unwrap();

        let tmp = std::env::temp_dir().join("forseti_test_chacha20.tfedb");
        std::fs::write(&tmp, &buf).unwrap();

        let loaded = DatabaseFile::deserialise(tmp.to_str().unwrap(), master).unwrap();

        assert_eq!(
            loaded.header.fields.encryption.to_u8(),
            db.header.fields.encryption.to_u8()
        );
        assert_eq!(
            loaded.header.fields.compression.to_u8(),
            db.header.fields.compression.to_u8()
        );
        assert_eq!(
            loaded.internal_content.entries.len(),
            db.internal_content.entries.len()
        );
        assert_eq!(
            loaded.internal_content.files.len(),
            db.internal_content.files.len()
        );
    }

    #[test]
    fn wrong_master_password_fails() {
        let db = sample_db(EncryptionAlgorithm::Aes, CompressionAlgorithm::GZip);
        let correct = b"correct_pw";
        let wrong = b"wrong_pw";

        let mut buf = Vec::new();
        db.serialise(&mut buf, correct).unwrap();

        let tmp = std::env::temp_dir().join("forseti_test_wrong_pw.tfedb");
        std::fs::write(&tmp, &buf).unwrap();

        let result = DatabaseFile::deserialise(tmp.to_str().unwrap(), wrong);
        match result {
            Ok(_) => panic!("deserialise unexpectedly succeeded with wrong password"),
            Err(err) => {
                assert!(matches!(
                    err.kind(),
                    std::io::ErrorKind::PermissionDenied | std::io::ErrorKind::InvalidData
                ));
            }
        }
    }
}
