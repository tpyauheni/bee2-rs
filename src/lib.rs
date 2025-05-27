#[allow(warnings)]
pub mod bindings {
    include!("../target/build/bindings.rs");
}

pub(crate) const ERR_OK: u32 = 0;

pub mod errors;

#[cfg(feature = "block")]
pub mod block;
#[cfg(feature = "belt")]
pub mod belt;
#[cfg(feature = "bign")]
pub mod bign;
#[cfg(feature = "brng")]
pub mod brng;
#[cfg(feature = "bash-hash")]
pub mod bash_hash;
