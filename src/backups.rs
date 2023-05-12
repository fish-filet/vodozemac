// Copyright 2023 Damir Jelić
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! ☣️  Support for Olms PkEncryption and PkDecryption
//!
//! This sucks, don't use it.

use crate::{types::Curve25519SecretKey, Curve25519PublicKey};

pub struct PkDecryption {
    key: Curve25519SecretKey,
    public_key: Curve25519PublicKey,
}

impl PkDecryption {
    pub fn new() -> Self {
        let key = Curve25519SecretKey::new();
        let public_key = Curve25519PublicKey::from(&key);

        Self {
            key,
            public_key,
        }

    }

    pub fn public_key(&self) -> Curve25519PublicKey {
        self.public_key
    }

    pub fn decrypt(&self, message: &Message) -> Vec<u8> {
        let shared_secret = self.key.diffie_hellman(&message.ephemeral_key);

        let shared_secret = hkdf::Hkdf::<sha2::Sha256>::extract(None, shared_secret.as_bytes());


        todo!()
    }
}

impl Default for PkDecryption {
    fn default() -> Self {
        Self::new()
    }
}

pub struct Message {
    pub ciphertext: Vec<u8>,
    pub mac: Vec<u8>,
    pub ephemeral_key: Curve25519PublicKey,
}

#[cfg(test)]
mod test {
    use crate::utilities::base64_decode;

    use super::*;
    use olm_rs::pk::{OlmPkEncryption, PkMessage};

    impl TryFrom<PkMessage> for Message {
        type Error = base64::DecodeError;

        fn try_from(value: PkMessage) -> Result<Self, Self::Error> {
            Ok(Self {
                ciphertext: base64_decode(value.ciphertext)?,
                mac: base64_decode(value.mac)?,
                ephemeral_key: Curve25519PublicKey::from_base64(&value.ephemeral_key).unwrap(),
            })
        }
    }
    
    #[test]
    fn decrypt() {
        let decryptor = PkDecryption::new();
        let public_key = decryptor.public_key();
        let encryptor = OlmPkEncryption::new(&public_key.to_base64());

        let message = "It's a secret to everybody";

        let encrypted = encryptor.encrypt(message);
        let encrypted = encrypted.try_into().unwrap();

        let decrypted = decryptor.decrypt(&encrypted);

        todo!()
    }
}
