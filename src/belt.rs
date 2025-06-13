use std::{ffi, rc::Rc};

#[cfg(feature = "belt-hmac")]
use crate::belt_hmac::BeltHmac;
<<<<<<< HEAD
#[cfg(feature = "block-padding")]
use crate::block::Block;
#[cfg(feature = "block-padding")]
use crate::errors::InvalidBlockError;
#[cfg(feature = "belt-pbkdf2")]
use crate::errors::{BeltError, BeltErrorKind};
use crate::{bindings, errors::Bee2Result};
=======
use crate::{bindings, errors::Bee2Result};
#[cfg(feature = "block-padding")]
use crate::block::Block;
#[cfg(feature = "belt-pbkdf2")]
use crate::errors::{BeltError, BeltErrorKind};
#[cfg(feature = "block-padding")]
use crate::errors::InvalidBlockError;
>>>>>>> 285bcd3 (Fixed errors, made "block-padding" a default feature, fixed warnings)

pub trait BeltKey {
    fn len() -> u8;
}

type ExpandedKey = Rc<[u32; 8]>;

macro_rules! to_encryption_algorithm {
    ($func_name: ident, $ret_type: ident, $len_func: ident, $start_func: ident, $use_iv: tt) => {
        pub fn $func_name(self, #[cfg($use_iv())] iv: [u8; 16]) -> $ret_type {
            let state_len: usize = unsafe { bindings::$len_func() };
            let mut state_vec = Vec::with_capacity(state_len);
            let state = state_vec.spare_capacity_mut();
            unsafe {
                bindings::$start_func(
                    state.as_mut_ptr() as *mut ffi::c_void,
                    self.key.as_ptr(),
                    Self::len().into(),
                    #[cfg($use_iv())]
                    iv.as_ptr(),
                );
            }
            unsafe {
                state_vec.set_len(state_len);
            }
            $ret_type {
                state: state_vec.into_boxed_slice(),
            }
        }
    };
    ($func_name: ident, $ret_type: ident, $len_func: ident, $start_func: ident) => {
        to_encryption_algorithm!($func_name, $ret_type, $len_func, $start_func, any);
    };
    ($func_name: ident, $ret_type: ident, $len_func: ident, $start_func: ident, use iv) => {
        to_encryption_algorithm!($func_name, $ret_type, $len_func, $start_func, all);
    };
}

macro_rules! key {
    ($name: ident, $len: expr) => {
        #[derive(Debug, Clone, PartialEq, Eq)]
        pub struct $name {
            key: Rc<[u8; $len]>,
        }

        impl $name {
            pub fn new(data: [u8; $len]) -> Self {
                Self {
                    key: Rc::new(data),
                }
            }

            pub fn get_bytes(&self) -> Rc<[u8; $len]> {
                self.key.clone()
            }

            pub fn expand(&self) -> BeltKey256 {
                let mut key: [u8; 32] = [0; 32];
                unsafe { bindings::beltKeyExpand(
                    key.as_mut_ptr(),
                    self.key.as_ptr(),
                    Self::len().into(),
                ); }
                BeltKey256 { key: Rc::new(key) }
            }

            fn expanded_bytes(&self) -> ExpandedKey {
                let mut key: [u32; 8] = [0; 8];
                unsafe { bindings::beltKeyExpand2(
                    key.as_mut_ptr(),
                    self.key.as_ptr(),
                    Self::len().into(),
                ); }
                Rc::new(key)
            }

            pub fn encrypt(&self, mut block: [u8; 16]) -> [u8; 16] {
                let key: ExpandedKey = self.expanded_bytes();
                unsafe { bindings::beltBlockEncr(
                    block.as_mut_ptr(),
                    key.as_ptr(),
                ); }
                block
            }

            pub fn decrypt(&self, mut block: [u8; 16]) -> [u8; 16] {
                let key: ExpandedKey = self.expanded_bytes();
                unsafe { bindings::beltBlockDecr(
                    block.as_mut_ptr(),
                    key.as_ptr(),
                ); }
                block
            }

            #[cfg(feature = "belt-wbl")]
            to_encryption_algorithm!(wbl, BeltWbl, beltWBL_keep, beltWBLStart);
            #[cfg(feature = "belt-ecb")]
            to_encryption_algorithm!(ecb, BeltEcb, beltECB_keep, beltECBStart);
            #[cfg(feature = "belt-cbc")]
            to_encryption_algorithm!(cbc, BeltCbc, beltCBC_keep, beltCBCStart, use iv);
            #[cfg(feature = "belt-cfb")]
            to_encryption_algorithm!(cfb, BeltCfb, beltCFB_keep, beltCFBStart, use iv);
            #[cfg(feature = "belt-ctr")]
            to_encryption_algorithm!(ctr, BeltCtr, beltCTR_keep, beltCTRStart, use iv);
            #[cfg(feature = "belt-dwp")]
            to_encryption_algorithm!(dwp, BeltDwp, beltDWP_keep, beltDWPStart, use iv);
            #[cfg(feature = "belt-che")]
            to_encryption_algorithm!(che, BeltChe, beltCHE_keep, beltCHEStart, use iv);
            #[cfg(feature = "belt-kwp")]
            to_encryption_algorithm!(kwp, BeltKwp, beltWBL_keep, beltWBLStart);
            #[cfg(feature = "belt-bde")]
            to_encryption_algorithm!(bde, BeltBde, beltBDE_keep, beltBDEStart, use iv);
            #[cfg(feature = "belt-hmac")]
            to_encryption_algorithm!(hmac, BeltHmac, beltHMAC_keep, beltHMACStart);
        }

        impl BeltKey for $name {
            fn len() -> u8 {
                $len
            }
        }
    };
}

key!(BeltKey128, 16);
key!(BeltKey192, 24);
key!(BeltKey256, 32);

#[cfg(feature = "belt-pbkdf2")]
impl BeltKey256 {
    pub fn pbkdf2(password: &[u8], iterations: usize, salt: &[u8]) -> Bee2Result<Self> {
        let mut key = [0u8; 32];
        let code = unsafe {
            bindings::beltPBKDF2(
                key.as_mut_ptr(),
                password.as_ptr(),
                password.len(),
                iterations,
                salt.as_ptr(),
                salt.len(),
            )
        };
        if code != 0 {
            Err(BeltError::new_box(BeltErrorKind::CodeError(code)))
        } else {
            Ok(Self { key: Rc::new(key) })
        }
    }
}

impl BeltKey256 {
    pub fn to_key192(self) -> BeltKey192 {
        BeltKey192 {
            key: Rc::new(self.key[..24].try_into().unwrap()),
        }
    }

    pub fn to_key192_unchecked(self) -> BeltKey192 {
        BeltKey192 {
            key: Rc::new(unsafe { self.key[..24].try_into().unwrap_unchecked() }),
        }
    }

    pub fn to_key128(self) -> BeltKey128 {
        BeltKey128 {
            key: Rc::new(self.key[..16].try_into().unwrap()),
        }
    }

    pub fn to_key128_unchecked(self) -> BeltKey128 {
        BeltKey128 {
            key: Rc::new(unsafe { self.key[..16].try_into().unwrap_unchecked() }),
        }
    }
}

impl BeltKey192 {
    pub fn to_key128(self) -> BeltKey128 {
        BeltKey128 {
            key: Rc::new(self.key[..16].try_into().unwrap()),
        }
    }

    pub fn to_key128_unchecked(self) -> BeltKey128 {
        BeltKey128 {
            key: Rc::new(unsafe { self.key[..16].try_into().unwrap_unchecked() }),
        }
    }
}

pub trait BeltEncryptionAlgorithm {
    fn encrypt(&mut self, plaintext: &[u8]) -> Box<[u8]>;
    fn decrypt(&mut self, ciphertext: Box<[u8]>) -> Bee2Result<Box<[u8]>>;
}

macro_rules! belt_encryption_algorithm {
    ($name: ident, $init_func: ident, $encrypt_func: ident, $decrypt_func: ident, $block_size: expr) => {
        #[derive(Debug, Clone, PartialEq, Eq)]
        pub struct $name {
            pub(crate) state: Box<[u8]>,
        }

        impl BeltEncryptionAlgorithm for $name {
            fn encrypt(&mut self, plaintext: &[u8]) -> Box<[u8]> {
                #[cfg(feature = "block-padding")]
                {
                    let padded_plaintext = Block::pad(&plaintext, $block_size);
                    let mut blocks: Vec<Box<[u8]>> = vec![];
                    for mut block in padded_plaintext {
                        unsafe {
                            bindings::$encrypt_func(
                                block.as_mut_ptr() as *mut ffi::c_void,
                                block.len(),
                                self.state.as_mut_ptr() as *mut ffi::c_void,
                            );
                        }
                        blocks.push(block);
                    }
                    let mut data: Vec<u8> = vec![];
                    for block in blocks {
                        data.extend(block);
                    }
                    data.into_boxed_slice()
                }
                #[cfg(not(feature = "block-padding"))]
                {
                    let plaintext: &mut [u8] = &mut plaintext.to_owned();
                    unsafe {
                        bindings::$encrypt_func(
                            plaintext.as_mut_ptr() as *mut ffi::c_void,
                            plaintext.len(),
                            self.state.as_mut_ptr() as *mut ffi::c_void,
                        );
                    }
                    Box::from(plaintext)
                }
            }

            fn decrypt(&mut self, mut ciphertext: Box<[u8]>) -> Bee2Result<Box<[u8]>> {
                #[cfg(feature = "block-padding")]
                {
                    if ciphertext.len() < $block_size || ciphertext.len() % $block_size != 0 {
                        return Err(InvalidBlockError::new_box());
                    }
                    let mut padded_plaintext: Vec<Box<[u8]>> = vec![];
                    for chunk in ciphertext.chunks_mut($block_size) {
                        unsafe {
                            bindings::$decrypt_func(
                                chunk.as_mut_ptr() as *mut ffi::c_void,
                                $block_size,
                                self.state.as_mut_ptr() as *mut ffi::c_void,
                            );
                        }
                        padded_plaintext.push(Box::from(chunk));
                    }
                    Block::unpad(padded_plaintext)
                }
                #[cfg(not(feature = "block-padding"))]
                {
                    unsafe {
                        bindings::$decrypt_func(
                            ciphertext.as_mut_ptr() as *mut ffi::c_void,
                            ciphertext.len(),
                            self.state.as_mut_ptr() as *mut ffi::c_void,
                        );
                    }
                    Ok(ciphertext)
                }
            }
        }
    };
}

#[cfg(feature = "belt-wbl")]
belt_encryption_algorithm!(BeltWbl, beltWBLStart, beltWBLStepE, beltWBLStepD, 32);
#[cfg(feature = "belt-ecb")]
belt_encryption_algorithm!(BeltEcb, beltECBStart, beltECBStepE, beltECBStepD, 16);
#[cfg(feature = "belt-cbc")]
belt_encryption_algorithm!(BeltCbc, beltCBCStart, beltCBCStepE, beltCBCStepD, 16);
#[cfg(feature = "belt-cfb")]
belt_encryption_algorithm!(BeltCfb, beltCFBStart, beltCFBStepE, beltCFBStepD, 16);
#[cfg(feature = "belt-ctr")]
belt_encryption_algorithm!(BeltCtr, beltCTRStart, beltCTRStepE, beltCTRStepE, 16);
#[cfg(feature = "belt-dwp")]
belt_encryption_algorithm!(BeltDwp, beltDWPStart, beltDWPStepE, beltDWPStepD, 16);
#[cfg(feature = "belt-che")]
belt_encryption_algorithm!(BeltChe, beltCHEStart, beltCHEStepE, beltCHEStepD, 16);
#[cfg(feature = "belt-kwp")]
belt_encryption_algorithm!(BeltKwp, beltWBLStart, beltWBLStepE, beltWBLStepD, 32);
#[cfg(feature = "belt-bde")]
belt_encryption_algorithm!(BeltBde, beltBDEStart, beltBDEStepE, beltBDEStepD, 16);
// TODO: SDE, FMT, KRP, HASH, HMAC, PBKDF2.

#[cfg(test)]
mod tests {
    use super::{BeltEncryptionAlgorithm, BeltKey128, BeltKey192, BeltKey256};

    macro_rules! perform_belt_test {
        ($key_init:expr, $mode:ident($($args:expr),*), $plaintext:literal $(,)?) => {
            let key = $key_init;
            let mut ctx = key.$mode($($args),*);
            let plaintext = $plaintext.as_bytes();
            let ciphertext = ctx.encrypt(plaintext);
            let original_plaintext = Box::from(plaintext);
            assert_ne!(original_plaintext, ciphertext);

            let key = $key_init;
            let mut ctx = key.$mode($($args),*);
            let decrypted_plaintext = ctx.decrypt(ciphertext).unwrap();
            assert_eq!(original_plaintext, decrypted_plaintext);
        };
    }

    macro_rules! perform_belt_tests {
        ($feature:literal, $mode:ident, $test_name:ident, $use_iv:ident) => {
            #[cfg(feature = $feature)]
            #[test]
            fn $test_name() {
                #[cfg($use_iv())]
                perform_belt_test!(
                    BeltKey128::new([123; 16]),
                    $mode([45; 16]),
                    "Hello, World! This is a test message",
                );
                #[cfg($use_iv())]
                perform_belt_test!(BeltKey192::new([234; 24]), $mode([56; 16]), "",);
                #[cfg($use_iv())]
                perform_belt_test!(BeltKey256::new([34; 32]), $mode([67; 16]), "tinymsg",);
                #[cfg(not($use_iv()))]
                perform_belt_test!(
                    BeltKey128::new([123; 16]),
                    $mode(),
                    "Hello, World! This is a test message",
                );
                #[cfg(not($use_iv()))]
                perform_belt_test!(BeltKey192::new([234; 24]), $mode(), "",);
                #[cfg(not($use_iv()))]
                perform_belt_test!(BeltKey256::new([34; 32]), $mode(), "tinymsg",);
            }
        };
        ($feature:literal, $mode:ident, $test_name:ident) => {
            perform_belt_tests!($feature, $mode, $test_name, any);
        };
        ($feature:literal, $mode:ident, $test_name:ident, use iv) => {
            perform_belt_tests!($feature, $mode, $test_name, all);
        };
    }

    perform_belt_tests!("belt-wbl", wbl, test_belt_wbl);
    perform_belt_tests!("belt-ecb", ecb, test_belt_ecb);
    perform_belt_tests!("belt-cbc", cbc, test_belt_cbc, use iv);
    perform_belt_tests!("belt-cfb", cfb, test_belt_cfb, use iv);
    perform_belt_tests!("belt-ctr", ctr, test_belt_ctr, use iv);
    perform_belt_tests!("belt-dwp", dwp, test_belt_dwp, use iv);
    perform_belt_tests!("belt-che", che, test_belt_che, use iv);
    perform_belt_tests!("belt-kwp", kwp, test_belt_kwp);
    perform_belt_tests!("belt-bde", bde, test_belt_bde, use iv);

    #[test]
    fn test_belt() {
        let key = BeltKey128::new([
            41, 242, 132, 45, 68, 168, 187, 151, 34, 16, 240, 116, 73, 207, 39, 223,
        ]);
        let block = [
            137, 130, 220, 72, 167, 6, 110, 155, 224, 30, 80, 122, 184, 167, 80, 23,
        ];
        let encrypted_block = key.encrypt(block);
        assert_ne!(block, encrypted_block);
        let key = BeltKey128::new([
            41, 242, 132, 45, 68, 168, 187, 151, 34, 16, 240, 116, 73, 207, 39, 223,
        ]);
        let decrypted_block = key.decrypt(encrypted_block);
        assert_eq!(block, decrypted_block);
        let invalid_key = BeltKey128::new([
            233, 238, 213, 220, 88, 33, 228, 255, 75, 37, 103, 125, 50, 243, 113, 11,
        ]);
        let invalid_block = invalid_key.decrypt(encrypted_block);
        assert_ne!(block, invalid_block);

        let key = BeltKey192::new([
            94, 85, 110, 244, 227, 175, 56, 16, 243, 112, 0, 106, 38, 183, 125, 26, 18, 19, 226,
            20, 239, 57, 226, 83,
        ]);
        let block = [
            71, 230, 7, 222, 154, 15, 72, 136, 129, 72, 24, 151, 161, 10, 134, 54,
        ];
        let encrypted_block = key.encrypt(block);
        assert_ne!(block, encrypted_block);
        let key = BeltKey192::new([
            94, 85, 110, 244, 227, 175, 56, 16, 243, 112, 0, 106, 38, 183, 125, 26, 18, 19, 226,
            20, 239, 57, 226, 83,
        ]);
        let decrypted_block = key.decrypt(encrypted_block);
        assert_eq!(block, decrypted_block);
        let invalid_key = BeltKey192::new([
            57, 14, 109, 214, 230, 0, 66, 189, 22, 64, 177, 215, 27, 226, 217, 4, 0, 214, 224, 197,
            170, 213, 189, 207,
        ]);
        let invalid_block = invalid_key.decrypt(encrypted_block);
        assert_ne!(block, invalid_block);

        let key = BeltKey256::new([
            8, 26, 176, 37, 208, 41, 187, 204, 194, 188, 125, 53, 59, 181, 224, 67, 178, 61, 214,
            41, 9, 59, 208, 149, 32, 237, 104, 114, 253, 148, 222, 53,
        ]);
        let block = [
            75, 164, 59, 107, 79, 141, 105, 104, 200, 145, 97, 206, 233, 194, 181, 103,
        ];
        let encrypted_block = key.encrypt(block);
        assert_ne!(block, encrypted_block);
        let key = BeltKey256::new([
            8, 26, 176, 37, 208, 41, 187, 204, 194, 188, 125, 53, 59, 181, 224, 67, 178, 61, 214,
            41, 9, 59, 208, 149, 32, 237, 104, 114, 253, 148, 222, 53,
        ]);
        let decrypted_block = key.decrypt(encrypted_block);
        assert_eq!(block, decrypted_block);
        let invalid_key = BeltKey256::new([
            237, 91, 46, 51, 68, 133, 214, 212, 135, 188, 32, 166, 142, 232, 204, 2, 191, 17, 204,
            100, 34, 215, 211, 234, 72, 179, 133, 225, 68, 149, 90, 122,
        ]);
        let invalid_block = invalid_key.decrypt(encrypted_block);
        assert_ne!(block, invalid_block);
    }

    #[cfg(feature = "belt-pbkdf2")]
    #[test]
    fn test_pbkdf2() {
        let key = BeltKey256::pbkdf2(
            "Som3 sup3r S3CUR3 p1ssw0rd!".as_bytes(),
            10000,
            &[11, 127, 226, 250, 126, 39, 123, 225],
        )
        .unwrap();
        assert_eq!(
            *key.key,
            [
                20, 222, 68, 203, 114, 84, 147, 135, 1, 175, 180, 211, 244, 236, 61, 67, 147, 13,
                151, 111, 24, 24, 112, 229, 154, 161, 20, 221, 140, 57, 214, 136
            ]
        );
        let key = BeltKey256::pbkdf2(
            &[104, 40, 39, 218, 217, 116, 248, 208, 96, 190, 83, 91],
            10000,
            &[
                180, 239, 28, 64, 223, 140, 173, 189, 76, 106, 243, 46, 4, 197, 78, 191, 173, 183,
                56, 219,
            ],
        )
        .unwrap();
        assert_eq!(
            *key.key,
            [
                1, 175, 189, 124, 213, 73, 197, 214, 87, 49, 44, 103, 101, 192, 41, 133, 164, 22,
                90, 74, 157, 172, 152, 74, 175, 80, 254, 114, 64, 2, 93, 105
            ]
        );
        let key = BeltKey256::pbkdf2(
            &[104, 40, 39, 218, 217, 116, 248, 208, 96, 190, 83, 91],
            100000,
            &[
                180, 239, 28, 64, 223, 140, 173, 189, 76, 106, 243, 46, 4, 197, 78, 191, 173, 183,
                56, 219,
            ],
        )
        .unwrap();
        assert_eq!(
            *key.key,
            [
                31, 82, 120, 128, 222, 244, 234, 180, 239, 193, 201, 102, 127, 52, 4, 125, 246, 54,
                130, 7, 18, 227, 203, 202, 247, 229, 212, 224, 152, 245, 128, 120
            ]
        );
        let key = BeltKey256::pbkdf2(
            &[104, 40, 39, 218, 217, 116, 248, 208, 96, 190, 83, 91],
            10000,
            &[],
        )
        .unwrap();
        assert_eq!(
            *key.key,
            [
                37, 132, 77, 133, 246, 23, 232, 35, 157, 107, 119, 89, 230, 204, 7, 153, 36, 198,
                45, 95, 16, 225, 193, 60, 184, 104, 210, 154, 107, 214, 158, 40
            ]
        );
    }

    #[test]
    fn test_key_shrink_cast() {
        let key256 = BeltKey256::new([
            55, 191, 218, 155, 143, 224, 205, 203, 249, 213, 113, 158, 45, 54, 68, 87, 244, 58,
            197, 167, 99, 85, 29, 33, 209, 229, 52, 173, 237, 161, 22, 229,
        ]);
        let key192 = key256.clone().to_key192();
        let key192u = key256.clone().to_key192_unchecked();
        assert_eq!(key192, key192u);
        assert_eq!(
            *key192.key,
            [
                55, 191, 218, 155, 143, 224, 205, 203, 249, 213, 113, 158, 45, 54, 68, 87, 244, 58,
                197, 167, 99, 85, 29, 33
            ]
        );
        let key128_256 = key256.clone().to_key128();
        let key128u_256 = key256.clone().to_key128_unchecked();
        let key128 = key192.clone().to_key128();
        let key128u = key192.clone().to_key128_unchecked();
        assert_eq!(key128_256, key128u_256);
        assert_eq!(key128_256, key128);
        assert_eq!(key128_256, key128u);
        assert_eq!(
            *key128_256.key,
            [
                55, 191, 218, 155, 143, 224, 205, 203, 249, 213, 113, 158, 45, 54, 68, 87
            ]
        );
        let plaintext = [
            37, 39, 57, 246, 12, 186, 61, 140, 229, 178, 45, 253, 98, 218, 68, 172,
        ];
        let correct_ciphertext = [
            182, 236, 239, 14, 35, 181, 245, 35, 105, 79, 235, 219, 21, 70, 154, 27,
        ];
        let ciphertext = key256.encrypt(plaintext);
        assert_eq!(ciphertext, correct_ciphertext);
        assert_eq!(key256.decrypt(ciphertext), plaintext);
        let plaintext = [
            37, 39, 57, 246, 12, 186, 61, 140, 229, 178, 45, 253, 98, 218, 68, 172,
        ];
        let correct_ciphertext = [
            143, 152, 166, 156, 6, 94, 158, 20, 17, 63, 185, 237, 144, 5, 144, 155,
        ];
        for key in [key192, key192u].iter() {
            let ciphertext = key.encrypt(plaintext);
            assert_eq!(ciphertext, correct_ciphertext);
            assert_eq!(key.decrypt(ciphertext), plaintext);
        }
        let plaintext = [
            37, 39, 57, 246, 12, 186, 61, 140, 229, 178, 45, 253, 98, 218, 68, 172,
        ];
        let correct_ciphertext = [
            33, 165, 92, 46, 210, 223, 94, 48, 45, 82, 143, 105, 142, 18, 130, 201,
        ];
        for key in [key128_256, key128u_256, key128, key128u].iter() {
            let ciphertext = key.encrypt(plaintext);
            assert_eq!(ciphertext, correct_ciphertext);
            assert_eq!(key.decrypt(ciphertext), plaintext);
        }
    }
}
