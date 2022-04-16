use core::fmt;

use doc_comment::doc_comment;
use kem::{
    generic_array::{
        typenum::{Unsigned, U16, U24, U32, U64},
        GenericArray,
    },
    Decapsulator as DecapsulatorTrait, EncappedKey as EncappedKeyTrait,
    Encapsulator as EncapsulatorTrait, Error,
};
use pqcrypto_traits::kem::{Ciphertext as CiphertextTrait, SharedSecret as SharedSecretTrait};
pub use pqcrypto_traits::kem::{PublicKey as PublicKeyTrait, SecretKey as SecretKeyTrait};
use rand_core::{CryptoRng, RngCore};

macro_rules! impl_kem {
    ($mod_name:ident, $comment:literal, $shared_secret_size:ty) => {
        doc_comment! {
            concat!(
                $comment,
                "\n# Example\n",
                "```\n",
                "use rand_core::OsRng;\n",
                "use pqcrypto_compat::kem::",
                stringify!($mod_name),
"::{
    keypair, Encapsulator, PublicKey, SecretKey,
};
use kem::{
    Decapsulator as DecapsulatorTrait, Encapsulator as EncapsulatorTrait
};

// Generate the recipient's keypair
let (pk_recip, sk_recip) = keypair();
// Encapsulate, getting the encapsulated key and shared secret
let (enc, ss1) = Encapsulator.try_encap(&mut OsRng, &pk_recip).unwrap();
// Decapsulate and get the shared secret
let ss2 = sk_recip.try_decap(&enc).unwrap();
// Shared secrets should be identical
assert_eq!(ss1, ss2);
```"
            ),
            pub mod $mod_name {
                use super::*;
                use pqcrypto::kem::$mod_name::{
                    encapsulate, decapsulate, public_key_bytes, secret_key_bytes
                };
                pub use pqcrypto::kem::$mod_name::{keypair, PublicKey, SecretKey};

                type NSecret = $shared_secret_size;

                /// Number of bytes in a public key
                pub const PUBLIC_KEY_SIZE: usize = public_key_bytes();
                /// Number of bytes in a secret key
                pub const SECRET_KEY_SIZE: usize = secret_key_bytes();
                /// Number of bytes in an encapsulated key. This is identical to
                /// `EncappedKey::NSecret::to_usize()`
                pub const ENCAPPED_KEY_SIZE: usize = NSecret::USIZE;

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
                    type NSecret = NSecret;
                    type RecipientPublicKey = PublicKey;
                    // None of these KEMs support authenticated encapsulation. Sender pubkey
                    // doesn't make sense.
                    type SenderPublicKey = ();
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
                    ) -> Result<(EncappedKey, GenericArray<u8, NSecret>), Error> {
                        let (shared_secret, ek) = encapsulate(recip_pubkey);
                        let ss_bytes = GenericArray::<u8, NSecret>::clone_from_slice(shared_secret.as_bytes());
                        Ok((EncappedKey(ek), ss_bytes))
                    }
                }

                impl DecapsulatorTrait<EncappedKey> for SecretKey {
                    /// Decapsulate the given encapsulated key, returning the shared secret. This
                    /// cannot fail.
                    fn try_decap(
                        &self,
                        encapped_key: &EncappedKey,
                    ) -> Result<GenericArray<u8, NSecret>, Error>
                    {
                        let shared_secret = decapsulate(&encapped_key.0, self);
                        let ss_bytes =
                            GenericArray::<u8, NSecret>::clone_from_slice(shared_secret.as_bytes());
                        Ok(ss_bytes)
                    }
                }
            }
        }
    }
}

#[cfg(feature = "pqcrypto-saber")]
impl_kem!(firesaber, "firesaber", U32);
#[cfg(feature = "pqcrypto-saber")]
impl_kem!(lightsaber, "lightsaber", U32);
#[cfg(feature = "pqcrypto-saber")]
impl_kem!(saber, "saber", U32);

#[cfg(feature = "pqcrypto-kyber")]
impl_kem!(kyber512, "kyber512", U32);
#[cfg(feature = "pqcrypto-kyber")]
impl_kem!(kyber51290s, "kyber51290s", U32);
#[cfg(feature = "pqcrypto-kyber")]
impl_kem!(kyber768, "kyber768", U32);
#[cfg(feature = "pqcrypto-kyber")]
impl_kem!(kyber76890s, "kyber76890s", U32);
#[cfg(feature = "pqcrypto-kyber")]
impl_kem!(kyber1024, "kyber1024", U32);
#[cfg(feature = "pqcrypto-kyber")]
impl_kem!(kyber102490s, "kyber102490s", U32);

#[cfg(feature = "pqcrypto-ntru")]
impl_kem!(ntruhps2048509, "ntruhps2048509", U32);
#[cfg(feature = "pqcrypto-ntru")]
impl_kem!(ntruhps2048677, "ntruhps2048677", U32);
#[cfg(feature = "pqcrypto-ntru")]
impl_kem!(ntruhps4096821, "ntruhps4096821", U32);
#[cfg(feature = "pqcrypto-ntru")]
impl_kem!(ntruhrss701, "ntruhrss701", U32);
#[cfg(feature = "pqcrypto-ntruprime")]
impl_kem!(ntrulpr653, "ntrulpr653", U32);
#[cfg(feature = "pqcrypto-ntruprime")]
impl_kem!(ntrulpr761, "ntrulpr761", U32);
#[cfg(feature = "pqcrypto-ntruprime")]
impl_kem!(ntrulpr857, "ntrulpr857", U32);
#[cfg(feature = "pqcrypto-ntruprime")]
impl_kem!(sntrup653, "sntrup653", U32);
#[cfg(feature = "pqcrypto-ntruprime")]
impl_kem!(sntrup761, "sntrup761", U32);
#[cfg(feature = "pqcrypto-ntruprime")]
impl_kem!(sntrup857, "sntrup857", U32);

#[cfg(feature = "pqcrypto-frodo")]
impl_kem!(frodokem640aes, "frodokem640aes", U16);
#[cfg(feature = "pqcrypto-frodo")]
impl_kem!(frodokem640shake, "frodokem640shake", U16);
#[cfg(feature = "pqcrypto-frodo")]
impl_kem!(frodokem976aes, "frodokem976aes", U24);
#[cfg(feature = "pqcrypto-frodo")]
impl_kem!(frodokem976shake, "frodokem976shake", U24);
#[cfg(feature = "pqcrypto-frodo")]
impl_kem!(frodokem1344aes, "frodokem1344aes", U32);
#[cfg(feature = "pqcrypto-frodo")]
impl_kem!(frodokem1344shake, "frodokem1344shake", U32);

#[cfg(feature = "pqcrypto-classicmceliece")]
impl_kem!(mceliece348864, "mceliece348864", U32);
#[cfg(feature = "pqcrypto-classicmceliece")]
impl_kem!(mceliece348864f, "mceliece348864f", U32);
#[cfg(feature = "pqcrypto-classicmceliece")]
impl_kem!(mceliece460896, "mceliece460896", U32);
#[cfg(feature = "pqcrypto-classicmceliece")]
impl_kem!(mceliece460896f, "mceliece460896f", U32);
#[cfg(feature = "pqcrypto-classicmceliece")]
impl_kem!(mceliece6688128, "mceliece6688128", U32);
#[cfg(feature = "pqcrypto-classicmceliece")]
impl_kem!(mceliece6688128f, "mceliece6688128f", U32);
#[cfg(feature = "pqcrypto-classicmceliece")]
impl_kem!(mceliece6960119, "mceliece6960119", U32);
#[cfg(feature = "pqcrypto-classicmceliece")]
impl_kem!(mceliece6960119f, "mceliece6960119f", U32);
#[cfg(feature = "pqcrypto-classicmceliece")]
impl_kem!(mceliece8192128, "mceliece8192128", U32);
#[cfg(feature = "pqcrypto-classicmceliece")]
impl_kem!(mceliece8192128f, "mceliece8192128f", U32);

#[cfg(feature = "pqcrypto-hqc")]
impl_kem!(hqcrmrs128, "hqcrmrs128", U64);
#[cfg(feature = "pqcrypto-hqc")]
impl_kem!(hqcrmrs192, "hqcrmrs192", U64);
#[cfg(feature = "pqcrypto-hqc")]
impl_kem!(hqcrmrs256, "hqcrmrs256", U64);
