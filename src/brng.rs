use std::ffi;

use crate::{
    ERR_OK, bindings,
    errors::{Bee2Result, BrngError, BrngErrorKind},
};

pub type Rng = bindings::gen_i;

pub trait ToBee2 {
    fn as_rng(&self) -> Rng;
    fn get_state(&self) -> Box<[u8]>;
}

macro_rules! next_number {
    ($fn_name:ident, $type:ty, $bytes:literal) => {
        fn $fn_name(&mut self) -> $type {
            let mut buffer = vec![0; $bytes];
            self.next_buffer(&mut buffer);
            // It doesn't matter which endianness are we using because those bytes are random.
            <$type>::from_ne_bytes(buffer.try_into().unwrap())
        }
    };
}

pub trait Brng {
    fn next_buffer(&mut self, buffer: &mut [u8]);

    next_number!(next_u8, u8, 1);
    next_number!(next_u16, u16, 2);
    next_number!(next_u32, u32, 4);
    next_number!(next_u64, u64, 8);
    next_number!(next_u128, u128, 16);
    next_number!(next_i8, i8, 1);
    next_number!(next_i16, i16, 2);
    next_number!(next_i32, i32, 4);
    next_number!(next_i64, i64, 8);
    next_number!(next_i128, i128, 16);
    next_number!(next_f32, f32, 4);
    next_number!(next_f64, f64, 8);
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CtrRng {
    state: Box<[u8]>,
}

impl CtrRng {
    pub fn new(key: [u8; 32], iv: Option<[u8; 32]>) -> Self {
        let state_len: usize = unsafe { bindings::brngCTR_keep() };
        let state_vec: Vec<u8> = vec![0; state_len];
        let mut state: Box<[u8]> = state_vec.into_boxed_slice();
        unsafe {
            bindings::brngCTRStart(
                state.as_mut_ptr() as *mut ffi::c_void,
                key.as_ptr(),
                match iv {
                    Some(iv) => iv.as_ptr(),
                    None => std::ptr::null(),
                },
            );
        }
        Self { state }
    }

    pub fn get_iv(&mut self) -> [u8; 32] {
        let mut iv: Box<[u8]> = Box::new([0; 32]);
        unsafe {
            bindings::brngCTRStepG(iv.as_mut_ptr(), self.state.as_mut_ptr() as *mut ffi::c_void)
        };
        (*iv).try_into().unwrap()
    }

    pub fn fill_buffer(buffer: &mut [u8], key: &[u8; 32], iv: &mut [u8; 32]) -> Bee2Result<()> {
        let code = unsafe {
            bindings::brngCTRRand(
                buffer.as_mut_ptr() as *mut ffi::c_void,
                buffer.len(),
                key.as_ptr(),
                iv.as_mut_ptr(),
            )
        };
        if code == ERR_OK {
            Ok(())
        } else {
            Err(BrngError::new_box(BrngErrorKind::CodeError(code)))
        }
    }
}

impl Brng for CtrRng {
    fn next_buffer(&mut self, buffer: &mut [u8]) {
        unsafe {
            bindings::brngCTRStepR(
                buffer.as_mut_ptr() as *mut ffi::c_void,
                buffer.len(),
                self.state.as_mut_ptr() as *mut ffi::c_void,
            );
        }
    }
}

impl ToBee2 for CtrRng {
    fn as_rng(&self) -> Rng {
        Some(bindings::brngCTRStepR)
    }

    fn get_state(&self) -> Box<[u8]> {
        self.state.clone()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HmacRng {
    state: Box<[u8]>,
}

impl HmacRng {
    pub fn new(key: &[u8], iv: &[u8]) -> Self {
        let state_len: usize = unsafe { bindings::brngHMAC_keep() };
        let state_vec: Vec<u8> = vec![0; state_len];
        let mut state: Box<[u8]> = state_vec.into_boxed_slice();
        unsafe {
            bindings::brngHMACStart(
                state.as_mut_ptr() as *mut ffi::c_void,
                key.as_ptr(),
                key.len(),
                iv.as_ptr(),
                iv.len(),
            );
        }
        Self { state }
    }

    pub fn fill_buffer(buffer: &mut [u8], key: &[u8], iv: &[u8]) -> Bee2Result<()> {
        let code = unsafe {
            bindings::brngHMACRand(
                buffer.as_mut_ptr() as *mut ffi::c_void,
                buffer.len(),
                key.as_ptr(),
                key.len(),
                iv.as_ptr(),
                iv.len(),
            )
        };
        if code == ERR_OK {
            Ok(())
        } else {
            Err(BrngError::new_box(BrngErrorKind::CodeError(code)))
        }
    }
}

impl Brng for HmacRng {
    fn next_buffer(&mut self, buffer: &mut [u8]) {
        unsafe {
            bindings::brngHMACStepR(
                buffer.as_mut_ptr() as *mut ffi::c_void,
                buffer.len(),
                self.state.as_mut_ptr() as *mut ffi::c_void,
            );
        }
    }
}

impl ToBee2 for HmacRng {
    fn as_rng(&self) -> Rng {
        Some(bindings::brngHMACStepR)
    }

    fn get_state(&self) -> Box<[u8]> {
        self.state.clone()
    }
}

#[cfg(test)]
mod tests {
    use crate::brng::Brng;

    use super::{CtrRng, HmacRng};

    #[test]
    fn test_ctr() {
        let iv = [
            160, 78, 75, 213, 247, 122, 26, 130, 210, 165, 152, 151, 127, 68, 13, 191, 218, 254,
            187, 106, 158, 184, 100, 249, 28, 175, 182, 11, 49, 238, 79, 159,
        ];
        let mut ctr = CtrRng::new(
            [
                158, 230, 31, 207, 83, 232, 111, 51, 4, 97, 42, 123, 19, 171, 124, 57, 27, 59, 94,
                169, 206, 98, 239, 7, 194, 79, 47, 223, 189, 60, 49, 18,
            ],
            Some(iv),
        );
        assert_eq!(ctr.get_iv(), iv);
        assert_eq!(ctr.next_u128(), 33223543754351378494114892648771219256);
        assert_eq!(ctr.next_u128(), 254770662039789769201022743983165607334);
        assert_eq!(ctr.next_i128(), 145450931704024937985007874937125038862);
        assert_eq!(ctr.next_u8(), 80);
        assert_eq!(ctr.next_i8(), 55);
        let mut bytes = [0; 50];
        ctr.next_buffer(&mut bytes);
        let correct_bytes = [
            147, 70, 47, 220, 55, 119, 251, 51, 229, 241, 36, 174, 253, 49, 72, 21, 200, 101, 45,
            138, 104, 221, 98, 163, 160, 193, 227, 145, 9, 125, 135, 40, 194, 199, 58, 243, 133,
            108, 177, 5, 195, 104, 34, 253, 70, 249, 135, 254, 229, 142,
        ];
        assert_eq!(bytes, correct_bytes);
        let mut bytes = [0; 10];
        let correct_bytes = [38, 63, 132, 211, 241, 76, 105, 55, 193, 59];
        let mut iv = [
            24, 86, 158, 178, 84, 209, 205, 75, 115, 252, 28, 234, 153, 108, 240, 32, 213, 68, 123,
            71, 73, 198, 180, 1, 91, 116, 158, 15, 46, 65, 143, 233,
        ];
        CtrRng::fill_buffer(
            &mut bytes,
            &[
                249, 185, 242, 52, 67, 251, 170, 132, 15, 99, 211, 198, 102, 161, 21, 158, 124,
                185, 156, 131, 232, 88, 234, 41, 1, 41, 218, 189, 147, 62, 245, 195,
            ],
            &mut iv,
        )
        .unwrap();
        assert_eq!(bytes, correct_bytes);
    }

    #[test]
    fn test_ctr_no_iv() {
        let mut ctr = CtrRng::new(
            [
                158, 230, 31, 207, 83, 232, 111, 51, 4, 97, 42, 123, 19, 171, 124, 57, 27, 59, 94,
                169, 206, 98, 239, 7, 194, 79, 47, 223, 189, 60, 49, 18,
            ],
            None,
        );
        assert_eq!(ctr.get_iv(), [0; 32]);
        assert_eq!(ctr.next_u128(), 120334134796420904791598703945664266902);
        assert_eq!(ctr.next_u128(), 304616918565234888971579775217524550230);
        assert_eq!(ctr.next_i128(), 6501559448512176569509678510543711220);
        assert_eq!(ctr.next_u8(), 225);
        assert_eq!(ctr.next_i8(), 58);
        let mut bytes = [0; 50];
        ctr.next_buffer(&mut bytes);
        let correct_bytes = [
            211, 55, 107, 155, 251, 113, 255, 200, 127, 108, 230, 144, 223, 93, 236, 116, 7, 149,
            27, 218, 196, 123, 86, 177, 110, 104, 252, 167, 195, 185, 148, 127, 12, 140, 102, 121,
            241, 233, 203, 135, 22, 127, 59, 0, 251, 255, 143, 174, 95, 28,
        ];
        assert_eq!(bytes, correct_bytes);
    }

    #[test]
    fn test_ctr_no_iv_with_hmac() {
        let mut ctr = CtrRng::new([182; 32], None);
        for (key_size, iv_size, correct_u128) in [
            (32, 32, 306374048185261273558272587736742924927),
            (32, 64, 235024047543251669815014272291028437617),
            (32, 500, 94447440104956993148363275917823358702),
            (16, 16, 254784175032821932408251532343037028667),
            (16, 32, 28967812749217125986967222953409779285),
            (16, 499, 114626956306424494098821140277093627270),
            (500, 500, 179485405194803047219406545339268619640),
        ] {
            let mut key = vec![0; key_size];
            let mut iv = vec![0; iv_size];
            ctr.next_buffer(&mut key);
            ctr.next_buffer(&mut iv);
            let mut hmac = HmacRng::new(&key, &iv);
            assert_eq!(hmac.next_u128(), correct_u128);
        }
    }
}
