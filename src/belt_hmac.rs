use std::ffi;

use crate::{
    ERR_OK, bindings,
    errors::{Bee2Result, BeltError, BeltErrorKind},
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BeltHmac {
    pub(crate) state: Box<[u8]>,
}

impl BeltHmac {
    pub fn update(&mut self, data: &[u8]) {
        unsafe {
            bindings::beltHMACStepA(
                data.as_ptr() as *const ffi::c_void,
                data.len(),
                self.state.as_mut_ptr() as *mut ffi::c_void,
            );
        }
    }

    pub fn get_mac(&mut self) -> [u8; 32] {
        let mut mac = [0; 32];
        unsafe {
            bindings::beltHMACStepG(
                mac.as_mut_ptr(),
                self.state.as_mut_ptr() as *mut ffi::c_void,
            );
        }
        mac
    }

    pub fn verify_mac(&mut self, mac: &[u8; 32]) -> bool {
        unsafe {
            bindings::beltHMACStepV(mac.as_ptr(), self.state.as_mut_ptr() as *mut ffi::c_void) != 0
        }
    }

    pub fn hmac(data: &[u8], key: &[u8]) -> Bee2Result<[u8; 32]> {
        let mut mac = [0; 32];
        let code = unsafe {
            bindings::beltHMAC(
                mac.as_mut_ptr(),
                data.as_ptr() as *const ffi::c_void,
                data.len(),
                key.as_ptr(),
                key.len(),
            )
        };
        if code != ERR_OK {
            Err(BeltError::new_box(BeltErrorKind::CodeError(code)))
        } else {
            Ok(mac)
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::belt::{BeltKey128, BeltKey192, BeltKey256};

    use super::BeltHmac;

    #[test]
    fn test_belt_hmac_static() {
        let hmac = BeltHmac::hmac(
            &[83; 5000],
            &[
                216, 173, 222, 130, 200, 235, 229, 122, 104, 148, 216, 238, 83, 69, 122, 108, 126,
                91, 212, 187, 154, 243, 23, 102, 135, 56, 135, 199, 89, 0, 101, 154,
            ],
        )
        .unwrap();
        let correct_hmac = [
            165, 74, 206, 198, 240, 22, 202, 208, 110, 79, 171, 130, 69, 124, 222, 61, 63, 100,
            250, 165, 16, 30, 63, 77, 198, 198, 94, 218, 214, 220, 202, 127,
        ];
        assert_eq!(hmac, correct_hmac);
        let hmac = BeltHmac::hmac(
            &[],
            &[
                135, 200, 75, 107, 194, 29, 178, 235, 115, 0, 154, 14, 88, 170, 15, 189, 241, 20,
                143, 11, 185, 209, 16, 14, 208, 194, 6, 229, 1, 166, 54, 136,
            ],
        )
        .unwrap();
        let correct_hmac = [
            37, 138, 120, 108, 243, 35, 180, 132, 186, 144, 174, 78, 211, 227, 243, 234, 146, 210,
            41, 77, 167, 199, 172, 108, 131, 188, 236, 110, 59, 128, 15, 67,
        ];
        assert_eq!(hmac, correct_hmac);
    }

    #[test]
    fn test_belt128_hmac_updates() {
        let key = BeltKey128::new([
            37, 101, 178, 62, 168, 75, 124, 9, 204, 144, 122, 70, 100, 226, 185, 110,
        ]);
        let mut hmac = key.hmac();
        let mac = hmac.get_mac();
        assert_eq!(
            mac,
            [
                0, 180, 59, 223, 166, 163, 251, 223, 201, 6, 93, 12, 43, 171, 122, 169, 81, 16,
                134, 208, 182, 126, 64, 154, 118, 209, 188, 203, 27, 57, 44, 89
            ]
        );
        assert!(hmac.verify_mac(&mac));
        hmac.update(&[50; 500]);
        let mac1 = hmac.get_mac();
        assert_eq!(
            mac1,
            [
                95, 255, 123, 94, 46, 79, 7, 153, 219, 96, 172, 116, 119, 65, 104, 12, 120, 189,
                20, 94, 12, 247, 145, 224, 35, 130, 10, 193, 177, 107, 190, 57
            ]
        );
        hmac.update(&[]);
        assert!(hmac.verify_mac(&mac1));
        let mac2 = hmac.get_mac();
        assert_eq!(mac1, mac2);
        hmac.update(&[50; 500]);
        let mac = hmac.get_mac();
        assert!(hmac.verify_mac(&mac));
        assert_eq!(
            mac,
            [
                47, 196, 21, 195, 229, 212, 93, 8, 186, 88, 169, 21, 211, 162, 238, 40, 60, 103,
                129, 108, 236, 85, 253, 144, 106, 98, 113, 199, 190, 131, 172, 205
            ]
        );
        hmac.update(&[0; 3]);
        let mac = hmac.get_mac();
        assert!(hmac.verify_mac(&mac));
        assert!(!hmac.verify_mac(&mac1));
        assert!(!hmac.verify_mac(&mac2));
        assert_eq!(
            mac,
            [
                112, 144, 131, 162, 242, 239, 235, 178, 45, 191, 87, 208, 197, 94, 46, 76, 107, 77,
                103, 93, 64, 178, 209, 234, 97, 83, 243, 242, 99, 211, 156, 56
            ]
        );
    }

    #[test]
    fn test_belt192_hmac_updates() {
        let key = BeltKey192::new([
            29, 223, 20, 26, 139, 55, 84, 169, 142, 227, 127, 153, 102, 245, 34, 191, 204, 19, 150,
            85, 219, 69, 4, 67,
        ]);
        let mut hmac = key.hmac();
        let mac = hmac.get_mac();
        assert_eq!(
            mac,
            [
                52, 93, 236, 251, 140, 180, 54, 222, 198, 186, 54, 135, 220, 116, 79, 101, 24, 127,
                5, 100, 138, 5, 90, 15, 105, 120, 235, 198, 151, 13, 141, 4
            ]
        );
        assert!(hmac.verify_mac(&mac));
        hmac.update(&[50; 500]);
        let mac1 = hmac.get_mac();
        assert_eq!(
            mac1,
            [
                34, 27, 138, 190, 92, 27, 43, 64, 12, 31, 109, 144, 221, 116, 49, 18, 56, 44, 215,
                130, 124, 227, 107, 119, 198, 167, 149, 127, 171, 167, 117, 38
            ]
        );
        hmac.update(&[]);
        assert!(hmac.verify_mac(&mac1));
        let mac2 = hmac.get_mac();
        assert_eq!(mac1, mac2);
        hmac.update(&[50; 500]);
        let mac = hmac.get_mac();
        assert!(hmac.verify_mac(&mac));
        assert_eq!(
            mac,
            [
                230, 155, 234, 105, 29, 59, 244, 140, 151, 178, 32, 40, 233, 182, 215, 178, 84,
                251, 22, 231, 200, 168, 52, 209, 246, 73, 53, 229, 161, 99, 31, 245
            ]
        );
        hmac.update(&[0; 3]);
        let mac = hmac.get_mac();
        assert!(hmac.verify_mac(&mac));
        assert!(!hmac.verify_mac(&mac1));
        assert!(!hmac.verify_mac(&mac2));
        assert_eq!(
            mac,
            [
                14, 222, 60, 83, 104, 199, 8, 86, 163, 230, 209, 13, 61, 212, 222, 34, 47, 163, 27,
                48, 236, 96, 17, 215, 74, 62, 0, 18, 124, 92, 123, 55
            ]
        );
    }

    #[test]
    fn test_belt256_hmac_updates() {
        let key = BeltKey256::new([
            246, 64, 28, 8, 205, 188, 188, 9, 223, 204, 57, 177, 223, 23, 219, 234, 80, 132, 175,
            214, 236, 28, 214, 184, 74, 13, 106, 172, 117, 37, 206, 203,
        ]);
        let mut hmac = key.hmac();
        let mac = hmac.get_mac();
        assert_eq!(
            mac,
            [
                67, 208, 26, 219, 86, 148, 14, 233, 203, 215, 123, 140, 89, 35, 97, 83, 125, 123,
                38, 61, 232, 8, 227, 0, 235, 227, 143, 143, 111, 132, 12, 110
            ]
        );
        assert!(hmac.verify_mac(&mac));
        hmac.update(&[50; 500]);
        let mac1 = hmac.get_mac();
        assert_eq!(
            mac1,
            [
                57, 238, 142, 7, 25, 32, 215, 28, 105, 221, 14, 68, 44, 241, 42, 164, 125, 211, 17,
                31, 163, 197, 165, 74, 108, 228, 108, 202, 221, 93, 31, 48
            ]
        );
        hmac.update(&[]);
        assert!(hmac.verify_mac(&mac1));
        let mac2 = hmac.get_mac();
        assert_eq!(mac1, mac2);
        hmac.update(&[50; 500]);
        let mac = hmac.get_mac();
        assert!(hmac.verify_mac(&mac));
        assert_eq!(
            mac,
            [
                253, 198, 247, 161, 9, 211, 255, 74, 88, 21, 61, 171, 10, 7, 182, 148, 184, 163,
                254, 167, 32, 38, 57, 145, 61, 183, 144, 126, 113, 142, 7, 60
            ]
        );
        hmac.update(&[0; 3]);
        let mac = hmac.get_mac();
        assert!(hmac.verify_mac(&mac));
        assert!(!hmac.verify_mac(&mac1));
        assert!(!hmac.verify_mac(&mac2));
        assert_eq!(
            mac,
            [
                126, 189, 205, 41, 28, 150, 105, 153, 87, 232, 93, 182, 81, 95, 51, 216, 24, 89,
                253, 4, 60, 196, 40, 17, 84, 137, 176, 49, 222, 112, 44, 78
            ]
        );
    }
}
