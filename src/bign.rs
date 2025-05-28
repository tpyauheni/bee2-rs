use std::ffi::{self, CString};

use crate::{bindings, brng, errors::{AnyError, Bee2Result, BignError}, ERR_OK};

#[derive(Clone)]
pub struct BignParameters {
    pub params: bindings::bign_params,
    pub config: BignParametersConfiguration,
}

#[derive(Clone)]
pub enum BignParametersConfiguration {
    B1,
    B2,
    B3
}

impl BignParametersConfiguration {
    pub fn as_str(&self) -> &'static str {
        match *self {
            BignParametersConfiguration::B1 => "1.2.112.0.2.0.34.101.45.3.1",
            BignParametersConfiguration::B2 => "1.2.112.0.2.0.34.101.45.3.2",
            BignParametersConfiguration::B3 => "1.2.112.0.2.0.34.101.45.3.3",
        }
    }

    pub fn as_cstring(&self) -> CString {
        CString::new(self.as_str()).unwrap()
    }
}

impl BignParameters {
    pub fn try_new(config: BignParametersConfiguration) -> Bee2Result<Self> {
        let mut params: bindings::bign_params = bindings::bign_params {
            l: 0,
            p: [0; 64],
            a: [0; 64],
            b: [0; 64],
            q: [0; 64],
            yG: [0; 64],
            seed: [0; 8],
        };
        let name = config.as_cstring();
        let code = unsafe { bindings::bignParamsStd(
            (&mut params) as *mut bindings::bign_params,
            name.as_ptr(),
        ) };
        if code != ERR_OK {
            Err(BignError::new_box(code))
        } else {
            Ok(Self {
                params,
                config,
            })
        }
    }

    pub fn validate(&self) -> Bee2Result<()> {
        let code = unsafe {
            bindings::bignParamsVal((&self.params) as *const bindings::bign_params)
        };
        if code == ERR_OK {
            Ok(())
        } else {
            Err(BignError::new_box(code))
        }
    }
}

pub struct BignKey {
    pub private_key: Box<[u8]>,
    pub public_key: Box<[u8]>,
    pub params: BignParameters,
}

impl BignKey {
    pub fn try_new(mut params: BignParameters, rng: &mut impl brng::ToBee2) -> Bee2Result<Self> {
        let l = params.params.l;
        let mut priv_key: Box<[u8]> = vec![0; l / 4].into_boxed_slice();
        let mut pub_key: Box<[u8]> = vec![0; l / 2].into_boxed_slice();

        let code = unsafe { bindings::bignKeypairGen(
            priv_key.as_mut_ptr(),
            pub_key.as_mut_ptr(),
            (&mut params.params) as *mut bindings::bign_params,
            rng.as_rng(),
            rng.get_state().as_mut_ptr() as *mut ffi::c_void,
        ) };
        if code != ERR_OK {
            Err(BignError::new_box(code))
        } else {
            Ok(Self {
                private_key: priv_key,
                public_key: pub_key,
                params,
            })
        }
    }

    pub fn try_load(
        params: BignParameters,
        public_key: &[u8],
        private_key: &[u8],
    ) -> Bee2Result<Self> {
        let key = Self {
            private_key: Box::from(private_key),
            public_key: Box::from(public_key),
            params,
        };
        key.validate_keypair()?;
        key.validate_public_key()?;
        key.params.validate()?;
        Ok(key)
    }

    pub fn validate_keypair(&self) -> Bee2Result<()> {
        let code = unsafe { bindings::bignKeypairVal(
            (&self.params.params) as *const bindings::bign_params,
            self.private_key.as_ptr(),
            self.public_key.as_ptr(),
        ) };
        if code == ERR_OK {
            Ok(())
        } else {
            Err(BignError::new_box(code))
        }
    }

    pub fn validate_public_key(&self) -> Bee2Result<()> {
        let code = unsafe { bindings::bignPubkeyVal(
            (&self.params.params) as *const bindings::bign_params,
            self.public_key.as_ptr(),
        ) };
        if code == ERR_OK {
            Ok(())
        } else {
            Err(BignError::new_box(code))
        }
    }

    pub fn diffie_hellman(
        &mut self,
        other_public_key: &[u8],
        result_len: usize,
    ) -> Bee2Result<Box<[u8]>> {
        let mut shared_key: Box<[u8]> = vec![0; result_len].into_boxed_slice();

        let code = unsafe { bindings::bignDH(
            shared_key.as_mut_ptr(),
            (&self.params.params) as *const bindings::bign_params,
            self.private_key.as_ptr(),
            other_public_key.as_ptr(),
            result_len,
        ) };
        if code != ERR_OK {
            Err(BignError::new_box(code))
        } else {
            Ok(shared_key)
        }
    }

    pub(crate) fn oid_to_der(oid: &str) -> Bee2Result<Box<[u8]>> {
        let mut der_len: usize = 0;
        let oid_cstr = CString::new(oid).map_err(|err| AnyError::new_box(Box::new(err)))?;

        let code = unsafe { bindings::bignOidToDER(
            std::ptr::null_mut(),
            (&mut der_len) as *mut usize,
            oid_cstr.as_ptr(),
        ) };
        if code != 0 {
            return Err(BignError::new_box(code));
        }

        let mut der: Box<[u8]> = vec![0; der_len].into_boxed_slice();
        let code = unsafe { bindings::bignOidToDER(
            der.as_mut_ptr(),
            (&mut der_len) as *mut usize,
            oid_cstr.as_ptr(),
        ) };
        if code == 0 {
            Ok(der)
        } else {
            Err(BignError::new_box(code))
        }
    }

    pub fn sign(
        &self,
        hash: &[u8],
        rng: &mut impl brng::ToBee2,
    ) -> Bee2Result<Box<[u8]>> {
        let l = self.params.params.l;

        if hash.len() != l / 4 {
            // `ERR_OK` is used here because it is the only constant that is guranteed to not be
            // used by original lib.
            return Err(BignError::new_box(ERR_OK));
        }

        let mut signature: Box<[u8]> = vec![0; 3 * l / 8].into_boxed_slice();
        let oid = &self.params.config;
        let der = Self::oid_to_der(oid.as_str())?;

        let code = unsafe { bindings::bignSign(
            signature.as_mut_ptr(),
            (&self.params.params) as *const bindings::bign_params,
            der.as_ptr(),
            der.len(),
            hash.as_ptr(),
            self.private_key.as_ptr(),
            rng.as_rng(),
            rng.get_state().as_mut_ptr() as *mut ffi::c_void,
        ) };
        if code != ERR_OK {
            Err(BignError::new_box(code))
        } else {
            Ok(signature)
        }
    }

    pub fn verify(&self, public_key: &[u8], hash: &[u8], signature: &[u8]) -> Bee2Result<()> {
        let oid = &self.params.config;
        let der = Self::oid_to_der(oid.as_str())?;

        let code = unsafe { bindings::bignVerify(
            (&self.params.params) as *const bindings::bign_params,
            der.as_ptr(),
            der.len(),
            hash.as_ptr(),
            signature.as_ptr(),
            public_key.as_ptr(),
        ) };
        if code == 0 {
            Ok(())
        } else {
            Err(BignError::new_box(code))
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::brng::CtrRng;

    use super::{BignKey, BignParameters, BignParametersConfiguration};

    #[test]
    fn test_sign_verify_b1() {
        let bign_params = BignParameters::try_new(BignParametersConfiguration::B1).unwrap();
        bign_params.validate().unwrap();
        let mut rng = CtrRng::new([127, 31, 135, 222, 51, 191, 216, 123, 84, 182, 194, 193, 119, 254,
            159, 175, 62, 37, 171, 78, 225, 111, 228, 109, 45, 214, 194, 213, 50, 158, 137, 62],
            Some([195, 41, 30, 22, 14, 36, 40, 112, 200, 64, 120, 40, 85, 48, 20, 214, 228,
            16, 24, 211, 90, 19, 10, 124, 240, 38, 16, 164, 189, 213, 152, 163]));
        let bign_key = BignKey::try_new(
            bign_params.clone(),
            &mut rng,
        ).unwrap();
        bign_key.validate_keypair().unwrap();
        bign_key.validate_public_key().unwrap();
        let hash1 = [85, 53, 50, 222, 230, 140, 139, 23, 193, 194, 203, 214, 168, 63, 36, 31, 51,
            249, 52, 80, 181, 196, 139, 113, 152, 233, 12, 117, 202, 92, 59, 23];
        let signature1 = bign_key.sign(&hash1, &mut rng).unwrap();
        let signature2 = bign_key.sign(&hash1, &mut rng).unwrap();
        // TODO: Check if it's fine that signature is the same despite function requiring `rng`.
        // assert_ne!(signature1, signature2);
        bign_key.verify(&bign_key.public_key, &hash1, &signature1).unwrap();
        bign_key.verify(&bign_key.public_key, &hash1, &signature2).unwrap();
        // TODO: Check if that signature really is valid
        let valid_signature = [46, 69, 252, 138, 238, 227, 110, 133, 175, 146, 52, 82, 116, 223,
            59, 150, 211, 49, 95, 232, 176, 53, 2, 128, 12, 40, 161, 139, 181, 140, 147, 3, 114,
            171, 98, 194, 146, 92, 33, 72, 63, 54, 216, 92, 168, 98, 74, 95];
        bign_key.verify(&bign_key.public_key, &hash1, &valid_signature).unwrap();
        let invalid_signature = [46, 69, 252, 138, 238, 227, 110, 133, 175, 146, 52, 82, 116, 223,
            59, 150, 211, 49, 95, 232, 176, 53, 2, 128, 12, 40, 161, 139, 181, 140, 147, 3, 114,
            171, 98, 194, 146, 92, 33, 72, 63, 54, 216, 92, 168, 98, 74, 96];
        bign_key.verify(&bign_key.public_key, &hash1, &invalid_signature).unwrap_err();
        bign_params.validate().unwrap();
        bign_key.validate_keypair().unwrap();
        bign_key.validate_public_key().unwrap();
    }

    #[test]
    fn test_sign_verify_b2() {
        let bign_params = BignParameters::try_new(BignParametersConfiguration::B2).unwrap();
        bign_params.validate().unwrap();
        let mut rng = CtrRng::new([127, 31, 135, 222, 51, 191, 216, 123, 84, 182, 194, 193, 119, 254, 159, 175, 62, 37, 171, 78, 225, 111, 228, 109, 45, 214, 194, 213, 50, 158, 137, 62], Some([195, 41, 30, 22, 14, 36, 40, 112, 200, 64, 120, 40, 85, 48, 20, 214, 228, 16, 24, 211, 90, 19, 10, 124, 240, 38, 16, 164, 189, 213, 152, 163]));
        let bign_key = BignKey::try_new(bign_params.clone(), &mut rng).unwrap();
        bign_key.validate_keypair().unwrap();
        bign_key.validate_public_key().unwrap();
        let hash1 = [201, 65, 149, 231, 9, 62, 52, 84, 31, 111, 216, 198, 52, 242, 250, 19, 186, 216, 130, 8, 100, 118, 188, 122, 34, 162, 32, 175, 42, 221, 57, 30, 152, 157, 99, 6, 241, 148, 66, 200, 37, 73, 31, 178, 177, 139, 74, 44];
        let signature1 = bign_key.sign(&hash1, &mut rng).unwrap();
        let signature2 = bign_key.sign(&hash1, &mut rng).unwrap();
        // TODO: Check if it's fine that signature is the same despite function requiring `rng`.
        // assert_ne!(signature1, signature2);
        bign_key.verify(&bign_key.public_key, &hash1, &signature1).unwrap();
        bign_key.verify(&bign_key.public_key, &hash1, &signature2).unwrap();
        // TODO: Check if that signature really is valid
        let valid_signature = [250, 72, 23, 69, 80, 129, 196, 35, 120, 252, 222, 204, 38, 156, 247, 26, 173, 35, 131, 5, 231, 141, 247, 183, 184, 62, 220, 241, 156, 194, 153, 44, 105, 145, 4, 124, 72, 74, 174, 48, 72, 76, 17, 134, 111, 105, 57, 10, 55, 61, 29, 191, 24, 93, 189, 87, 233, 151, 244, 184, 220, 214, 254, 194, 123, 129, 188, 76, 156, 212, 199, 148];
        bign_key.verify(&bign_key.public_key, &hash1, &valid_signature).unwrap();
        let invalid_signature = [250, 72, 23, 69, 80, 129, 196, 35, 120, 252, 222, 204, 38, 156, 247, 26, 173, 35, 131, 5, 231, 141, 247, 183, 184, 62, 220, 241, 156, 194, 153, 44, 105, 145, 4, 124, 72, 74, 174, 48, 72, 76, 17, 134, 111, 105, 57, 10, 55, 61, 29, 191, 24, 93, 189, 87, 233, 151, 244, 184, 220, 214, 254, 194, 123, 129, 188, 76, 156, 212, 199, 149];
        bign_key.verify(&bign_key.public_key, &hash1, &invalid_signature).unwrap_err();
        bign_params.validate().unwrap();
        bign_key.validate_keypair().unwrap();
        bign_key.validate_public_key().unwrap();
    }

    #[test]
    fn test_sign_verify_b3() {
        let bign_params = BignParameters::try_new(BignParametersConfiguration::B3).unwrap();
        bign_params.validate().unwrap();
        let mut rng = CtrRng::new([127, 31, 135, 222, 51, 191, 216, 123, 84, 182, 194, 193, 119, 254, 159, 175, 62, 37, 171, 78, 225, 111, 228, 109, 45, 214, 194, 213, 50, 158, 137, 62], Some([195, 41, 30, 22, 14, 36, 40, 112, 200, 64, 120, 40, 85, 48, 20, 214, 228, 16, 24, 211, 90, 19, 10, 124, 240, 38, 16, 164, 189, 213, 152, 163]));
        let bign_key = BignKey::try_new(bign_params.clone(), &mut rng).unwrap();
        bign_key.validate_keypair().unwrap();
        bign_key.validate_public_key().unwrap();
        let hash1 = [205, 15, 121, 40, 31, 33, 13, 6, 163, 218, 44, 52, 168, 249, 227, 209, 13, 220, 185, 115, 173, 151, 35, 216, 109, 108, 219, 2, 251, 81, 148, 197, 77, 94, 21, 207, 100, 238, 254, 191, 34, 11, 172, 133, 101, 65, 42, 148, 230, 164, 111, 108, 240, 100, 40, 132, 128, 18, 90, 75, 192, 160, 170, 200];
        let signature1 = bign_key.sign(&hash1, &mut rng).unwrap();
        let signature2 = bign_key.sign(&hash1, &mut rng).unwrap();
        // TODO: Check if it's fine that signature is the same despite function requiring `rng`.
        // assert_ne!(signature1, signature2);
        bign_key.verify(&bign_key.public_key, &hash1, &signature1).unwrap();
        bign_key.verify(&bign_key.public_key, &hash1, &signature2).unwrap();
        // TODO: Check if that signature really is valid
        let valid_signature = [128, 169, 147, 27, 236, 72, 183, 38, 112, 93, 192, 204, 157, 177, 127, 228, 2, 147, 162, 14, 71, 64, 66, 54, 29, 70, 226, 168, 97, 182, 39, 114, 139, 13, 217, 194, 32, 71, 12, 182, 170, 21, 23, 111, 7, 100, 181, 155, 76, 129, 86, 244, 74, 50, 115, 56, 109, 111, 80, 152, 219, 110, 211, 154, 31, 71, 113, 238, 99, 163, 139, 243, 122, 121, 147, 217, 234, 207, 28, 55, 23, 74, 101, 215, 222, 228, 182, 114, 137, 220, 117, 238, 79, 219, 98, 129];
        bign_key.verify(&bign_key.public_key, &hash1, &valid_signature).unwrap();
        let invalid_signature = [128, 169, 147, 27, 236, 72, 183, 38, 112, 93, 192, 204, 157, 177, 127, 228, 2, 147, 162, 14, 71, 64, 66, 54, 29, 70, 226, 168, 97, 182, 39, 114, 139, 13, 217, 194, 32, 71, 12, 182, 170, 21, 23, 111, 7, 100, 181, 155, 76, 129, 86, 244, 74, 50, 115, 56, 109, 111, 80, 152, 219, 110, 211, 154, 31, 71, 113, 238, 99, 163, 139, 243, 122, 121, 147, 217, 234, 207, 28, 55, 23, 74, 101, 215, 222, 228, 182, 114, 137, 220, 117, 238, 79, 219, 98, 130];
        bign_key.verify(&bign_key.public_key, &hash1, &invalid_signature).unwrap_err();
        bign_params.validate().unwrap();
        bign_key.validate_keypair().unwrap();
        bign_key.validate_public_key().unwrap();
    }

    #[test]
    fn test_diffie_hellman() {
        let bign_params = BignParameters::try_new(BignParametersConfiguration::B1).unwrap();
        bign_params.validate().unwrap();
        let mut rng = CtrRng::new([30, 138, 167, 215, 184, 0, 145, 201, 150, 217, 60, 134, 43, 246, 123, 184, 131, 114, 192, 207, 197, 63, 222, 23, 132, 232, 188, 200, 109, 231, 16, 47], None);
        let mut bign_key = BignKey::try_new(bign_params.clone(), &mut rng).unwrap();
        bign_key.validate_keypair().unwrap();
        bign_key.validate_public_key().unwrap();

        let mut rng2 = CtrRng::new([55, 205, 97, 114, 13, 64, 27, 233, 108, 221, 167, 134, 46, 68, 196, 139, 94, 225, 130, 54, 137, 63, 246, 44, 116, 229, 10, 237, 102, 235, 142, 112], None);
        let mut bign_key2 = BignKey::try_new(bign_params.clone(), &mut rng2).unwrap();
        bign_key2.validate_keypair().unwrap();
        bign_key2.validate_public_key().unwrap();

        for size in 1..=64 {
            let shared_key1 = bign_key.diffie_hellman(&bign_key2.public_key, size).unwrap();
            let shared_key2 = bign_key2.diffie_hellman(&bign_key.public_key, size).unwrap();
            assert_eq!(shared_key1, shared_key2);
            assert_eq!(shared_key1.len(), size);
        }

        bign_params.validate().unwrap();
        bign_key.validate_keypair().unwrap();
        bign_key.validate_public_key().unwrap();
        bign_key2.validate_keypair().unwrap();
        bign_key2.validate_public_key().unwrap();
    }
}
