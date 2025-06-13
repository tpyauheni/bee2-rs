use std::ffi;

use crate::{
    ERR_OK, bindings,
    errors::{BashError, BashErrorKind, Bee2Result},
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BashHash {
    state: Vec<u8>,
    resistance_level: u16,
}

impl BashHash {
    pub fn try_new(resistance_level: u16) -> Bee2Result<Self> {
        if resistance_level == 0 || resistance_level % 16 != 0 {
            return Err(BashError::new_box(BashErrorKind::InvalidResistanceLevel));
        }

        let state_len: usize = unsafe { bindings::bashHash_keep() };
        let mut state: Vec<u8> = vec![];
        state.reserve_exact(state_len);

        unsafe {
            bindings::bashHashStart(
                state.as_mut_ptr() as *mut ffi::c_void,
                resistance_level as usize,
            );
        }

        Ok(Self {
            state,
            resistance_level,
        })
    }

    pub fn new(resistance_level: u16) -> Self {
        Self::try_new(resistance_level).unwrap()
    }

    /// # Safety
    /// Calling this method if `try_new` returns `Err` is undefined behavior.
    pub unsafe fn new_unchecked(resistance_level: u16) -> Self {
        unsafe { Self::try_new(resistance_level).unwrap_unchecked() }
    }

    pub fn update(&mut self, data: &[u8]) {
        unsafe {
            bindings::bashHashStepH(
                data.as_ptr() as *const ffi::c_void,
                data.len(),
                self.state.as_mut_ptr() as *mut ffi::c_void,
            );
        }
    }

    pub fn get_hash_with_length(&mut self, length: u8) -> Bee2Result<Box<[u8]>> {
        if length as u16 > self.resistance_level / 4 {
            return Err(BashError::new_box(BashErrorKind::HashLengthIsTooLarge));
        }

        let mut hash: Box<[u8]> = vec![0; length as usize].into_boxed_slice();
        unsafe {
            bindings::bashHashStepG(
                hash.as_mut_ptr(),
                length as usize,
                self.state.as_mut_ptr() as *mut ffi::c_void,
            );
        }
        Ok(hash)
    }

    pub fn get_hash(&mut self) -> Box<[u8]> {
        unsafe {
            self.get_hash_with_length((self.resistance_level / 4) as u8)
                .unwrap_unchecked()
        }
    }

    pub fn verify_hash(&mut self, hash: &[u8]) -> bool {
        unsafe {
            bindings::bashHashStepV(
                hash.as_ptr(),
                hash.len(),
                self.state.as_mut_ptr() as *mut ffi::c_void,
            ) != 0
        }
    }

    pub fn hash(data: &[u8], resistance_level: u16) -> Bee2Result<Box<[u8]>> {
        if resistance_level == 0 || resistance_level % 16 != 0 {
            return Err(BashError::new_box(BashErrorKind::InvalidResistanceLevel));
        }

        let mut hash: Box<[u8]> = vec![0; resistance_level as usize / 4].into_boxed_slice();
        let code = unsafe {
            bindings::bashHash(
                hash.as_mut_ptr(),
                resistance_level as usize,
                data.as_ptr() as *const ffi::c_void,
                data.len(),
            )
        };

        if code != ERR_OK {
            Err(BashError::new_box(BashErrorKind::CodeError(code)))
        } else {
            Ok(hash)
        }
    }
}

macro_rules! define_bash_hash {
    ($name:ident, $resistance_level:literal) => {
        #[derive(Debug, Clone, PartialEq, Eq)]
        pub struct $name {
            hash: BashHash,
        }

        impl Default for $name {
            fn default() -> Self {
                unsafe {
                    Self {
                        hash: BashHash::new_unchecked($resistance_level),
                    }
                }
            }
        }

        impl $name {
            pub fn new() -> Self {
                Self::default()
            }

            pub fn update(&mut self, data: &[u8]) {
                self.hash.update(data);
            }

            pub fn get_hash(&mut self) -> Box<[u8]> {
                self.hash.get_hash()
            }

            pub fn verify_hash(&mut self, hash: &[u8]) -> bool {
                self.hash.verify_hash(hash)
            }

            pub fn hash(data: &[u8]) -> Bee2Result<Box<[u8]>> {
                BashHash::hash(data, $resistance_level)
            }

            pub fn into_raw_hash(self) -> BashHash {
                self.hash
            }
        }
    };
}

define_bash_hash!(Bash256, 128);
define_bash_hash!(Bash384, 192);
define_bash_hash!(Bash512, 256);

#[cfg(test)]
mod tests {
    use crate::bash_hash::{Bash384, Bash512};

    use super::Bash256;

    #[test]
    fn test_bash256() {
        let data = "Hello, World!".as_bytes();
        let correct_hash = [
            91, 97, 179, 136, 66, 158, 187, 141, 160, 202, 202, 115, 238, 171, 211, 142, 1, 250,
            163, 11, 60, 230, 39, 164, 88, 86, 117, 107, 112, 144, 165, 96,
        ];
        for _i in 0..5 {
            let mut bash = Bash256::new();
            bash.update(data);
            let hash = bash.get_hash();
            assert!(bash.verify_hash(&hash));
            assert_eq!(*hash, correct_hash);
            let hash = Bash256::hash(data).unwrap();
            assert!(bash.verify_hash(&hash));
            assert_eq!(*hash, correct_hash);
        }
        let mut data2: Vec<u8> = vec![];
        for i in 0..=255 {
            data2.push(i);
        }
        let correct_hash = [
            221, 100, 89, 90, 56, 159, 14, 44, 24, 19, 13, 199, 21, 105, 227, 103, 232, 137, 178,
            179, 221, 128, 190, 188, 183, 69, 146, 129, 35, 148, 184, 247,
        ];
        for _i in 0..5 {
            let mut bash = Bash256::new();
            bash.update(&data2);
            let hash = bash.get_hash();
            assert!(bash.verify_hash(&hash));
            assert_eq!(*hash, correct_hash);
            let hash = Bash256::hash(&data2).unwrap();
            assert!(bash.verify_hash(&hash));
            assert_eq!(*hash, correct_hash);
        }
        let correct_hash = [
            89, 27, 255, 89, 114, 173, 66, 255, 210, 123, 135, 238, 233, 90, 116, 7, 164, 114, 68,
            129, 125, 71, 14, 228, 138, 59, 85, 65, 77, 169, 80, 112,
        ];
        for _i in 0..5 {
            let mut bash = Bash256::new();
            bash.update(data);
            bash.update(&data2);
            let hash = bash.get_hash();
            assert!(bash.verify_hash(&hash));
            assert_eq!(*hash, correct_hash);
        }
    }

    #[test]
    fn test_bash384() {
        let data = "Hello, World!".as_bytes();
        let correct_hash = [
            79, 110, 64, 84, 203, 45, 157, 123, 144, 192, 143, 160, 59, 192, 179, 148, 5, 171, 191,
            240, 73, 79, 181, 242, 206, 200, 198, 235, 251, 17, 86, 182, 121, 245, 79, 221, 200,
            19, 251, 194, 221, 184, 142, 29, 164, 31, 92, 154,
        ];
        for _i in 0..5 {
            let mut bash = Bash384::new();
            bash.update(data);
            let hash = bash.get_hash();
            assert!(bash.verify_hash(&hash));
            assert_eq!(*hash, correct_hash);
            let hash = Bash384::hash(data).unwrap();
            assert!(bash.verify_hash(&hash));
            assert_eq!(*hash, correct_hash);
        }
        let mut data2: Vec<u8> = vec![];
        for i in 0..=255 {
            data2.push(i);
        }
        let correct_hash = [
            123, 77, 194, 2, 63, 236, 251, 29, 106, 55, 12, 86, 93, 95, 224, 156, 126, 218, 151,
            99, 175, 205, 195, 99, 96, 187, 184, 27, 12, 67, 234, 3, 141, 131, 168, 148, 20, 1,
            200, 27, 233, 221, 195, 2, 123, 247, 89, 106,
        ];
        for _i in 0..5 {
            let mut bash = Bash384::new();
            bash.update(&data2);
            let hash = bash.get_hash();
            assert!(bash.verify_hash(&hash));
            assert_eq!(*hash, correct_hash);
            let hash = Bash384::hash(&data2).unwrap();
            assert!(bash.verify_hash(&hash));
            assert_eq!(*hash, correct_hash);
        }
        let correct_hash = [
            201, 157, 79, 161, 10, 201, 201, 213, 216, 181, 25, 143, 26, 134, 156, 98, 28, 98, 212,
            153, 154, 187, 48, 17, 228, 230, 227, 208, 187, 85, 55, 126, 231, 106, 29, 250, 153,
            218, 138, 5, 151, 209, 247, 206, 148, 101, 182, 94,
        ];
        for _i in 0..5 {
            let mut bash = Bash384::new();
            bash.update(data);
            bash.update(&data2);
            let hash = bash.get_hash();
            assert!(bash.verify_hash(&hash));
            assert_eq!(*hash, correct_hash);
        }
    }

    #[test]
    fn test_bash512() {
        let data = "Hello, World!".as_bytes();
        let correct_hash = [
            250, 208, 4, 147, 34, 214, 6, 56, 32, 182, 120, 156, 202, 91, 88, 81, 167, 219, 79,
            242, 223, 206, 223, 133, 28, 59, 49, 68, 55, 13, 248, 64, 242, 70, 222, 220, 62, 117,
            55, 18, 66, 213, 56, 138, 124, 21, 132, 103, 128, 194, 25, 169, 86, 76, 31, 139, 108,
            166, 213, 129, 82, 150, 55, 2,
        ];
        for _i in 0..5 {
            let mut bash = Bash512::new();
            bash.update(data);
            let hash = bash.get_hash();
            assert!(bash.verify_hash(&hash));
            assert_eq!(*hash, correct_hash);
            let hash = Bash512::hash(data).unwrap();
            assert!(bash.verify_hash(&hash));
            assert_eq!(*hash, correct_hash);
        }
        let mut data2: Vec<u8> = vec![];
        for i in 0..=255 {
            data2.push(i);
        }
        let correct_hash = [
            148, 113, 183, 23, 22, 121, 51, 99, 112, 164, 125, 52, 152, 20, 239, 9, 181, 173, 22,
            167, 122, 114, 194, 167, 9, 247, 180, 182, 150, 148, 36, 103, 8, 29, 56, 115, 126, 104,
            26, 94, 205, 151, 217, 89, 176, 37, 144, 241, 195, 197, 206, 4, 237, 98, 171, 140, 222,
            34, 232, 16, 18, 192, 139, 67,
        ];
        for _i in 0..5 {
            let mut bash = Bash512::new();
            bash.update(&data2);
            let hash = bash.get_hash();
            assert!(bash.verify_hash(&hash));
            assert_eq!(*hash, correct_hash);
            let hash = Bash512::hash(&data2).unwrap();
            assert!(bash.verify_hash(&hash));
            assert_eq!(*hash, correct_hash);
        }
        let correct_hash = [
            240, 24, 5, 96, 225, 132, 42, 129, 181, 221, 236, 23, 245, 17, 114, 217, 175, 26, 35,
            139, 52, 254, 226, 72, 84, 119, 172, 126, 45, 9, 195, 86, 4, 37, 25, 75, 252, 49, 55,
            82, 120, 190, 80, 2, 83, 94, 62, 185, 230, 92, 243, 243, 254, 242, 200, 150, 115, 178,
            180, 229, 2, 225, 232, 196,
        ];
        for _i in 0..5 {
            let mut bash = Bash512::new();
            bash.update(data);
            bash.update(&data2);
            let hash = bash.get_hash();
            assert!(bash.verify_hash(&hash));
            assert_eq!(*hash, correct_hash);
        }
    }
}
