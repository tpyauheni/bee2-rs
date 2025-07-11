#[allow(warnings)]
pub mod bindings {
    include!("../target/build/bindings.rs");
}

pub const ERR_OK: u32 = 0;

pub mod errors;

#[cfg(feature = "bash-hash")]
pub mod bash_hash;
#[cfg(feature = "belt")]
pub mod belt;
#[cfg(feature = "belt-hmac")]
pub mod belt_hmac;
#[cfg(feature = "bign")]
pub mod bign;
#[cfg(feature = "block")]
pub mod block;
#[cfg(feature = "brng")]
pub mod brng;
