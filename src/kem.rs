use core::fmt;

use doc_comment::doc_comment;
use kem::{
    generic_array::{typenum::U32, GenericArray},
    Decapsulator as DecapsulatorTrait, EncappedKey as EncappedKeyTrait,
    Encapsulator as EncapsulatorTrait, Error,
};
use pqcrypto_traits::kem::{Ciphertext as CiphertextTrait, SharedSecret as SharedSecretTrait};
use rand_core::{CryptoRng, RngCore};

macro_rules! impl_kem {
    ($mod_name:ident, $comment:literal, $ss_size:ty) => {
        doc_comment! {
            concat!(
                $comment,
                "\n# Example\n",
                "```\n",
                "use rand_core::OsRng;",
                "use pqcrypto_compat::kem::",
                stringify!($mod_name),
                "::{keypair, Encapsulator, PublicKey, SecretKey};",
                "
use kem::{
    Decapsulator as DecapsulatorTrait,
    EncappedKey as EncappedKeyTrait,
    Encapsulator as EncapsulatorTrait
};

// Set up the recip keypair
let (pk_recip, sk_recip) = keypair();
// Encapsulate
let (ek, ss1) = Encapsulator.try_encap(&mut OsRng, &pk_recip).unwrap();
// Decapsulate
let ss2 = sk_recip.try_decap(&ek).unwrap();
// Shared secrets should be identical
assert_eq!(ss1, ss2);
```"
            ),
            pub mod $mod_name {
                use super::*;
                use pqcrypto::kem::$mod_name::{encapsulate, decapsulate};
                pub use pqcrypto::kem::$mod_name::{keypair, PublicKey, SecretKey};


                type NSecret = $ss_size;

                pub struct EncappedKey(pqcrypto::kem::$mod_name::Ciphertext);
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
                    type SenderPublicKey = PublicKey;
                    type RecipientPublicKey = PublicKey;
                }

                impl EncapsulatorTrait<EncappedKey> for Encapsulator {
                    /// Encapsulate to the given recipient. Due to the underlying PQC implementation, this function
                    /// DOES NOT use the given RNG. Rather, it samples its own randomness independently.
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
                    fn try_decap(&self, encapped_key: &EncappedKey) -> Result<GenericArray<u8, NSecret>, Error> {
                        let shared_secret = decapsulate(&encapped_key.0, self);
                        let ss_bytes = GenericArray::<u8, NSecret>::clone_from_slice(shared_secret.as_bytes());
                        Ok(ss_bytes)
                    }
                }
            }
        }
    }
}

impl_kem!(firesaber, "firesaber", U32);
