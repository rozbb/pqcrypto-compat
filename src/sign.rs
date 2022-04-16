use core::fmt;
use doc_comment::doc_comment;
use pqcrypto_traits::sign::DetachedSignature as DetachedSignatureTrait;
use signature::{Error, Signature as SignatureTrait, Signer, Verifier};

pub use pqcrypto_traits::sign::{PublicKey as PublicKeyTrait, SecretKey as SecretKeyTrait};

macro_rules! impl_sign_verify {
    ($mod_name:ident, $comment:literal) => {
        doc_comment! {
            concat!(
                $comment,
                "\n# Example\n",
                "```\n",
                "use pqcrypto_compat::sign::",
                stringify!($mod_name),
                "::{keypair, Signature};",
                "
use signature::{Signer, Verifier};

let message: Vec<u8> = vec![0, 1, 2, 3, 4, 5];
let (pk, sk) = keypair();
let sig = sk.sign(&message);
pk.verify(&message, &sig).unwrap();
```"
            ),
            pub mod $mod_name {
                use super::*;
                use pqcrypto::sign::$mod_name::{
                    detached_sign, verify_detached_signature, DetachedSignature,
                };

                pub use pqcrypto::sign::$mod_name::{keypair, PublicKey, SecretKey};

                // We implement the bare minimum in order to make this compatible with
                // RustCrypto's traits

                #[derive(Copy, Clone)]
                pub struct Signature(DetachedSignature);

                impl AsRef<[u8]> for Signature {
                    fn as_ref(&self) -> &[u8] {
                        self.as_bytes()
                    }
                }

                impl fmt::Debug for Signature {
                    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
                        f.debug_tuple("Signature").field(&self.as_bytes()).finish()
                    }
                }

                impl SignatureTrait for Signature {
                    fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
                        DetachedSignature::from_bytes(bytes)
                            .map_err(|_| Error::default())
                            .map(Signature)
                    }
                }

                impl Signer<Signature> for SecretKey {
                    fn try_sign(&self, msg: &[u8]) -> Result<Signature, Error> {
                        Ok(Signature(detached_sign(msg, self)))
                    }
                }

                impl Verifier<Signature> for PublicKey {
                    fn verify(&self, msg: &[u8], signature: &Signature) -> Result<(), Error> {
                        verify_detached_signature(&signature.0, msg, &self)
                            .map_err(|_| Error::default())
                    }
                }
            }
        }
    };
}

#[cfg(feature = "pqcrypto-dilithium")]
impl_sign_verify!(dilithium2, "dilithium2");
#[cfg(feature = "pqcrypto-dilithium")]
impl_sign_verify!(dilithium3, "dilithium3");
#[cfg(feature = "pqcrypto-dilithium")]
impl_sign_verify!(dilithium5, "dilithium5");

#[cfg(feature = "pqcrypto-falcon")]
impl_sign_verify!(falcon512, "falcon-512");
#[cfg(feature = "pqcrypto-falcon")]
impl_sign_verify!(falcon1024, "falcon-1024");

#[cfg(feature = "pqcrypto-rainbow")]
impl_sign_verify!(rainbowicircumzenithal, "rainbowI-circumzenithal");
#[cfg(feature = "pqcrypto-rainbow")]
impl_sign_verify!(rainbowiclassic, "rainbowI-classic");
#[cfg(feature = "pqcrypto-rainbow")]
impl_sign_verify!(rainbowicompressed, "rainbowI-compressed");
#[cfg(feature = "pqcrypto-rainbow")]
impl_sign_verify!(rainbowiiicircumzenithal, "rainbowIII-circumzenithal");
#[cfg(feature = "pqcrypto-rainbow")]
impl_sign_verify!(rainbowiiiclassic, "rainbowIII-classic");
#[cfg(feature = "pqcrypto-rainbow")]
impl_sign_verify!(rainbowiiicompressed, "rainbowIII-compressed");
#[cfg(feature = "pqcrypto-rainbow")]
impl_sign_verify!(rainbowvcircumzenithal, "rainbowV-circumzenithal");
#[cfg(feature = "pqcrypto-rainbow")]
impl_sign_verify!(rainbowvclassic, "rainbowV-classic");
#[cfg(feature = "pqcrypto-rainbow")]
impl_sign_verify!(rainbowvcompressed, "rainbowV-compressed");

#[cfg(feature = "pqcrypto-sphincsplus")]
impl_sign_verify!(sphincsharaka128frobust, "sphincs-haraka-128f-robust");
#[cfg(feature = "pqcrypto-sphincsplus")]
impl_sign_verify!(sphincsharaka128fsimple, "sphincs-haraka-128f-simple");
#[cfg(feature = "pqcrypto-sphincsplus")]
impl_sign_verify!(sphincsharaka128srobust, "sphincs-haraka-128s-robust");
#[cfg(feature = "pqcrypto-sphincsplus")]
impl_sign_verify!(sphincsharaka128ssimple, "sphincs-haraka-128s-simple");
#[cfg(feature = "pqcrypto-sphincsplus")]
impl_sign_verify!(sphincsharaka192frobust, "sphincs-haraka-192f-robust");
#[cfg(feature = "pqcrypto-sphincsplus")]
impl_sign_verify!(sphincsharaka192fsimple, "sphincs-haraka-192f-simple");
#[cfg(feature = "pqcrypto-sphincsplus")]
impl_sign_verify!(sphincsharaka192srobust, "sphincs-haraka-192s-robust");
#[cfg(feature = "pqcrypto-sphincsplus")]
impl_sign_verify!(sphincsharaka192ssimple, "sphincs-haraka-192s-simple");
#[cfg(feature = "pqcrypto-sphincsplus")]
impl_sign_verify!(sphincsharaka256frobust, "sphincs-haraka-256f-robust");
#[cfg(feature = "pqcrypto-sphincsplus")]
impl_sign_verify!(sphincsharaka256fsimple, "sphincs-haraka-256f-simple");
#[cfg(feature = "pqcrypto-sphincsplus")]
impl_sign_verify!(sphincsharaka256srobust, "sphincs-haraka-256s-robust");
#[cfg(feature = "pqcrypto-sphincsplus")]
impl_sign_verify!(sphincsharaka256ssimple, "sphincs-haraka-256s-simple");
#[cfg(feature = "pqcrypto-sphincsplus")]
impl_sign_verify!(sphincssha256128frobust, "sphincs-sha256-128f-robust");
#[cfg(feature = "pqcrypto-sphincsplus")]
impl_sign_verify!(sphincssha256128fsimple, "sphincs-sha256-128f-simple");
#[cfg(feature = "pqcrypto-sphincsplus")]
impl_sign_verify!(sphincssha256128srobust, "sphincs-sha256-128s-robust");
#[cfg(feature = "pqcrypto-sphincsplus")]
impl_sign_verify!(sphincssha256128ssimple, "sphincs-sha256-128s-simple");
#[cfg(feature = "pqcrypto-sphincsplus")]
impl_sign_verify!(sphincssha256192frobust, "sphincs-sha256-192f-robust");
#[cfg(feature = "pqcrypto-sphincsplus")]
impl_sign_verify!(sphincssha256192fsimple, "sphincs-sha256-192f-simple");
#[cfg(feature = "pqcrypto-sphincsplus")]
impl_sign_verify!(sphincssha256192srobust, "sphincs-sha256-192s-robust");
#[cfg(feature = "pqcrypto-sphincsplus")]
impl_sign_verify!(sphincssha256192ssimple, "sphincs-sha256-192s-simple");
#[cfg(feature = "pqcrypto-sphincsplus")]
impl_sign_verify!(sphincssha256256frobust, "sphincs-sha256-256f-robust");
#[cfg(feature = "pqcrypto-sphincsplus")]
impl_sign_verify!(sphincssha256256fsimple, "sphincs-sha256-256f-simple");
#[cfg(feature = "pqcrypto-sphincsplus")]
impl_sign_verify!(sphincssha256256srobust, "sphincs-sha256-256s-robust");
#[cfg(feature = "pqcrypto-sphincsplus")]
impl_sign_verify!(sphincssha256256ssimple, "sphincs-sha256-256s-simple");
#[cfg(feature = "pqcrypto-sphincsplus")]
impl_sign_verify!(sphincsshake256128frobust, "sphincs-shake256-128f-robust");
#[cfg(feature = "pqcrypto-sphincsplus")]
impl_sign_verify!(sphincsshake256128fsimple, "sphincs-shake256-128f-simple");
#[cfg(feature = "pqcrypto-sphincsplus")]
impl_sign_verify!(sphincsshake256128srobust, "sphincs-shake256-128s-robust");
#[cfg(feature = "pqcrypto-sphincsplus")]
impl_sign_verify!(sphincsshake256128ssimple, "sphincs-shake256-128s-simple");
#[cfg(feature = "pqcrypto-sphincsplus")]
impl_sign_verify!(sphincsshake256192frobust, "sphincs-shake256-192f-robust");
#[cfg(feature = "pqcrypto-sphincsplus")]
impl_sign_verify!(sphincsshake256192fsimple, "sphincs-shake256-192f-simple");
#[cfg(feature = "pqcrypto-sphincsplus")]
impl_sign_verify!(sphincsshake256192srobust, "sphincs-shake256-192s-robust");
#[cfg(feature = "pqcrypto-sphincsplus")]
impl_sign_verify!(sphincsshake256192ssimple, "sphincs-shake256-192s-simple");
#[cfg(feature = "pqcrypto-sphincsplus")]
impl_sign_verify!(sphincsshake256256frobust, "sphincs-shake256-256f-robust");
#[cfg(feature = "pqcrypto-sphincsplus")]
impl_sign_verify!(sphincsshake256256fsimple, "sphincs-shake256-256f-simple");
#[cfg(feature = "pqcrypto-sphincsplus")]
impl_sign_verify!(sphincsshake256256srobust, "sphincs-shake256-256s-robust");
#[cfg(feature = "pqcrypto-sphincsplus")]
impl_sign_verify!(sphincsshake256256ssimple, "sphincs-shake256-256s-simple");
