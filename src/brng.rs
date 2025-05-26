use std::ffi;

use crate::bindings;

pub type Rng = bindings::gen_i;

pub trait ToBee2 {
    fn as_rng(&self) -> Rng;
    fn get_state(&self) -> Box<[u8]>;
}

#[derive(Clone)]
pub struct CtrRng {
    state: Box<[u8]>,
}

impl CtrRng {
    pub fn new(key: [u8; 32], iv: Option<[u8; 32]>) -> Self {
        let state_len: usize = unsafe { bindings::brngCTR_keep() };
        let state_vec: Vec<u8> = vec![0; state_len];
        let mut state: Box<[u8]> = state_vec.into_boxed_slice();
        unsafe { bindings::brngCTRStart(
            state.as_mut_ptr() as *mut ffi::c_void,
            key.as_ptr(),
            match iv {
                Some(iv) => iv.as_ptr(),
                None => std::ptr::null(),
            },
        ); }
        Self {
            state,
        }
    }

    pub fn get_iv(&mut self) -> [u8; 32] {
        let mut iv: Box<[u8]> = Box::new([0; 32]);
        unsafe { bindings::brngCTRStepG(
            iv.as_mut_ptr(),
            self.state.as_mut_ptr() as *mut ffi::c_void,
        ) };
        (*iv).try_into().unwrap()
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

#[derive(Clone)]
pub struct HmacRng {
    state: Box<[u8]>,
}

impl HmacRng {
    pub fn new(key: &[u8], iv: &[u8]) -> Self {
        let state_len: usize = unsafe { bindings::brngHMAC_keep() };
        let state_vec: Vec<u8> = vec![0; state_len];
        let mut state: Box<[u8]> = state_vec.into_boxed_slice();
        unsafe { bindings::brngHMACStart(
            state.as_mut_ptr() as *mut ffi::c_void,
            key.as_ptr(),
            key.len(),
            iv.as_ptr(),
            iv.len(),
        ); }
        Self {
            state,
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
