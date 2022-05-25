use core::fmt;

use doc_comment::doc_comment;
use kem::{
    generic_array::{
        typenum::{self, Unsigned},
        GenericArray,
    },
    Decapsulator as DecapsulatorTrait, EncappedKey as EncappedKeyTrait,
    Encapsulator as EncapsulatorTrait, Error, SharedSecret,
};
use pqcrypto_traits::kem::{Ciphertext as CiphertextTrait, SharedSecret as SharedSecretTrait};
pub use pqcrypto_traits::kem::{PublicKey as PublicKeyTrait, SecretKey as SecretKeyTrait};
use rand_core::{CryptoRng, RngCore};

macro_rules! impl_kem {
    ($mod_name:ident, $comment:literal, $encapped_key_size:ty, $shared_secret_size:ty) => {
        doc_comment! {
            concat!(
                $comment,
                "\n# Example\n",
                "```\n",
                "use rand_core::OsRng;\n",
                "use pqcrypto_compat::kem::",
                stringify!($mod_name),
        "::{
    keypair, EncappedKey, Encapsulator, PublicKey, SecretKey,
};
use kem::{
    Decapsulator as DecapsulatorTrait, EncappedKey as EncappedKeyTrait,
    Encapsulator as EncapsulatorTrait,
};

// Generate the recipient's keypair
let (pk_recip, sk_recip) = keypair();
// Encapsulate, getting the encapsulated key and shared secret
let (enc, ss1) = Encapsulator.try_encap(&mut OsRng, &pk_recip).unwrap();
// Serialize and deserialize the encapsulated key
let enc = EncappedKey::from_bytes(enc.as_bytes()).unwrap();
// Decapsulate and get the shared secret
let ss2 = sk_recip.try_decap(&enc).unwrap();
// Shared secrets should be identical
assert_eq!(ss1.as_bytes(), ss2.as_bytes());
```"
            ),
            pub mod $mod_name {
                use super::*;
                use pqcrypto::kem::$mod_name::{
                    encapsulate, decapsulate, public_key_bytes, secret_key_bytes
                };
                pub use pqcrypto::kem::$mod_name::{keypair, PublicKey, SecretKey};

                type SharedSecretSize = $shared_secret_size;
                type EncappedKeySize = $encapped_key_size;

                // Define helpful public constants

                /// Number of bytes in a public key.
                pub const PUBLIC_KEY_SIZE: usize = public_key_bytes();
                /// Number of bytes in a secret key.
                pub const SECRET_KEY_SIZE: usize = secret_key_bytes();
                /// Number of bytes in a shared secret. This is identical to
                /// `EncappedKey::NSecret::to_usize()`.
                pub const SHARE_SECRET_SIZE: usize = NSecret::USIZE;
                /// Number of bytes in an encapsulated key. This is identical to
                /// `EncappedKey::NEnc::to_usize()`.
                pub const ENCAPPED_KEY_SIZE: usize = NEnc::USIZE;

                /// An encapsulated key. This is what the recipient uses to derive the shared
                /// secret.
                pub struct EncappedKey(pqcrypto::kem::$mod_name::Ciphertext);

                /// An object that creates new encapsulated keys. This is an empty struct.
                pub struct Encapsulator;

                impl fmt::Debug for EncappedKey {
                    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
                        f.debug_tuple("EncappedKey")
                            .field(&self.0.as_bytes())
                            .finish()
                    }
                }

                impl AsRef<[u8]> for EncappedKey {
                    fn as_ref(&self) -> &[u8] {
                        self.0.as_bytes()
                    }
                }

                impl EncappedKeyTrait for EncappedKey {
                    type NEnc = NEnc;
                    type NSecret = NSecret;
                    type RecipientPublicKey = PublicKey;

                    // None of these KEMs support authenticated encapsulation. Sender pubkey
                    // doesn't make sense.
                    type SenderPublicKey = ();

                    fn from_bytes(bytes: &GenericArray<u8, Self::NEnc>) -> Result<Self, Error> {
                        pqcrypto::kem::$mod_name::Ciphertext::from_bytes(bytes.as_slice())
                            .map(EncappedKey)
                            .map_err(|_| Error)
                    }
                }

                impl EncapsulatorTrait<EncappedKey> for Encapsulator {
                    /// Encapsulate to the given recipient, returning the encapsulated key and the
                    /// shared secret. This cannot fail.
                    ///
                    /// **Note:** Due to the underlying PQC implementation, this function DOES NOT
                    /// use the given RNG. Rather, it samples its own randomness independently.
                    fn try_encap<R: RngCore + CryptoRng>(
                        &self,
                        _: &mut R,
                        recip_pubkey: &PublicKey,
                    ) -> Result<(EncappedKey, SharedSecret<EncappedKey>), Error> {
                        let (shared_secret, ek) = encapsulate(recip_pubkey);
                        let ss_bytes = GenericArray::clone_from_slice(shared_secret.as_bytes());
                        Ok((EncappedKey(ek), SharedSecret::<EncappedKey>::new(ss_bytes)))
                    }
                }

                impl DecapsulatorTrait<EncappedKey> for SecretKey {
                    /// Decapsulate the given encapsulated key, returning the shared secret. This
                    /// cannot fail.
                    fn try_decap(
                        &self,
                        encapped_key: &EncappedKey,
                    ) -> Result<SharedSecret<EncappedKey>, Error>
                    {
                        let shared_secret = decapsulate(&encapped_key.0, self);
                        let ss_bytes = GenericArray::clone_from_slice(shared_secret.as_bytes());
                        Ok(SharedSecret::new(ss_bytes))
                    }
                }
            }
        }
    };
}

// Define all the type-level constants that are too big to be autogenerated by typenum
use kem::generic_array::typenum::consts::*;
type U1025 = typenum::op!(U1000 + U25);
type U1039 = typenum::op!(U1000 + U39);
type U1088 = typenum::op!(U1000 + U88);
type U1184 = typenum::op!(U1000 + U184);
type U1230 = typenum::op!(U1000 + U230);
type U1138 = typenum::op!(U1000 + U138);
type U1167 = typenum::op!(U1000 + U167);
type U1312 = typenum::op!(U1000 + U312);
type U1349 = typenum::op!(U1000 + U349);
type U1455 = typenum::op!(U1000 + U455);
type U1472 = typenum::op!(U1000 + U472);
type U1477 = typenum::op!(U1000 + U477);
type U1568 = typenum::op!(U1000 + U568);
type U1583 = typenum::op!(U1000 + U583);
type U1842 = typenum::op!(U1000 + U842);
type U1847 = typenum::op!(U1000 + U847);
type U1975 = typenum::op!(U1000 + U975);
type U4481 = typenum::op!(U4 * U1000 + U481);
type U9026 = typenum::op!(U9 * U1000 + U26);
type U9720 = typenum::op!(U9 * U1000 + U720);
type U14469 = typenum::op!(U14 * U1000 + U469);
type U15744 = typenum::op!(U15 * U1000 + U744);
type U21632 = typenum::op!(U21 * U1000 + U632);

// Now define all the KEMs. Format is: (name, str_name, encapped key size, shared secret size)

#[cfg(feature = "pqcrypto-saber")]
impl_kem!(lightsaber, "lightsaber", U736, U32);
#[cfg(feature = "pqcrypto-saber")]
impl_kem!(firesaber, "firesaber", U1472, U32);
#[cfg(feature = "pqcrypto-saber")]
impl_kem!(saber, "saber", U1088, U32);

#[cfg(feature = "pqcrypto-kyber")]
impl_kem!(kyber512, "kyber512", U768, U32);
#[cfg(feature = "pqcrypto-kyber")]
impl_kem!(kyber51290s, "kyber51290s", U768, U32);
#[cfg(feature = "pqcrypto-kyber")]
impl_kem!(kyber768, "kyber768", U1088, U32);
#[cfg(feature = "pqcrypto-kyber")]
impl_kem!(kyber76890s, "kyber76890s", U1088, U32);
#[cfg(feature = "pqcrypto-kyber")]
impl_kem!(kyber1024, "kyber1024", U1568, U32);
#[cfg(feature = "pqcrypto-kyber")]
impl_kem!(kyber102490s, "kyber102490s", U1568, U32);

#[cfg(feature = "pqcrypto-ntru")]
impl_kem!(ntruhps2048509, "ntruhps2048509", U699, U32);
#[cfg(feature = "pqcrypto-ntru")]
impl_kem!(ntruhps2048677, "ntruhps2048677", U930, U32);
#[cfg(feature = "pqcrypto-ntru")]
impl_kem!(ntruhps4096821, "ntruhps4096821", U1230, U32);
#[cfg(feature = "pqcrypto-ntru")]
impl_kem!(ntruhps40961229, "ntruhps40961229", U1842, U32);
#[cfg(feature = "pqcrypto-ntru")]
impl_kem!(ntruhrss701, "ntruhrss701", U1138, U32);

#[cfg(feature = "pqcrypto-ntruprime")]
impl_kem!(ntrulpr653, "ntrulpr653", U1025, U32);
#[cfg(feature = "pqcrypto-ntruprime")]
impl_kem!(ntrulpr761, "ntrulpr761", U1167, U32);
#[cfg(feature = "pqcrypto-ntruprime")]
impl_kem!(ntrulpr857, "ntrulpr857", U1312, U32);
#[cfg(feature = "pqcrypto-ntruprime")]
impl_kem!(ntrulpr953, "ntrulpr953", U1477, U32);
#[cfg(feature = "pqcrypto-ntruprime")]
impl_kem!(ntrulpr1013, "ntrulpr1013", U1583, U32);
#[cfg(feature = "pqcrypto-ntruprime")]
impl_kem!(ntrulpr1277, "ntrulpr1277", U1975, U32);
#[cfg(feature = "pqcrypto-ntruprime")]
impl_kem!(sntrup653, "sntrup653", U897, U32);
#[cfg(feature = "pqcrypto-ntruprime")]
impl_kem!(sntrup761, "sntrup761", U1039, U32);
#[cfg(feature = "pqcrypto-ntruprime")]
impl_kem!(sntrup857, "sntrup857", U1184, U32);
#[cfg(feature = "pqcrypto-ntruprime")]
impl_kem!(sntrup953, "sntrup953", U1349, U32);
#[cfg(feature = "pqcrypto-ntruprime")]
impl_kem!(sntrup1013, "sntrup1013", U1455, U32);
#[cfg(feature = "pqcrypto-ntruprime")]
impl_kem!(sntrup1277, "sntrup1277", U1847, U32);

#[cfg(feature = "pqcrypto-frodo")]
impl_kem!(frodokem640aes, "frodokem640aes", U9720, U16);
#[cfg(feature = "pqcrypto-frodo")]
impl_kem!(frodokem640shake, "frodokem640shake", U9720, U16);
#[cfg(feature = "pqcrypto-frodo")]
impl_kem!(frodokem976aes, "frodokem976aes", U15744, U24);
#[cfg(feature = "pqcrypto-frodo")]
impl_kem!(frodokem976shake, "frodokem976shake", U15744, U24);
#[cfg(feature = "pqcrypto-frodo")]
impl_kem!(frodokem1344aes, "frodokem1344aes", U21632, U32);
#[cfg(feature = "pqcrypto-frodo")]
impl_kem!(frodokem1344shake, "frodokem1344shake", U21632, U32);

#[cfg(feature = "pqcrypto-classicmceliece")]
impl_kem!(mceliece348864, "mceliece348864", U128, U32);
#[cfg(feature = "pqcrypto-classicmceliece")]
impl_kem!(mceliece348864f, "mceliece348864f", U128, U32);
#[cfg(feature = "pqcrypto-classicmceliece")]
impl_kem!(mceliece460896, "mceliece460896", U188, U32);
#[cfg(feature = "pqcrypto-classicmceliece")]
impl_kem!(mceliece460896f, "mceliece460896f", U188, U32);
#[cfg(feature = "pqcrypto-classicmceliece")]
impl_kem!(mceliece6688128, "mceliece6688128", U240, U32);
#[cfg(feature = "pqcrypto-classicmceliece")]
impl_kem!(mceliece6688128f, "mceliece6688128f", U240, U32);
#[cfg(feature = "pqcrypto-classicmceliece")]
impl_kem!(mceliece6960119, "mceliece6960119", U226, U32);
#[cfg(feature = "pqcrypto-classicmceliece")]
impl_kem!(mceliece6960119f, "mceliece6960119f", U226, U32);
#[cfg(feature = "pqcrypto-classicmceliece")]
impl_kem!(mceliece8192128, "mceliece8192128", U240, U32);
#[cfg(feature = "pqcrypto-classicmceliece")]
impl_kem!(mceliece8192128f, "mceliece8192128f", U240, U32);

#[cfg(feature = "pqcrypto-hqc")]
impl_kem!(hqcrmrs128, "hqcrmrs128", U4481, U64);
#[cfg(feature = "pqcrypto-hqc")]
impl_kem!(hqcrmrs192, "hqcrmrs192", U9026, U64);
#[cfg(feature = "pqcrypto-hqc")]
impl_kem!(hqcrmrs256, "hqcrmrs256", U14469, U64);
