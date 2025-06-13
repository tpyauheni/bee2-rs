use std::error::Error;

pub trait Bee2Error: Error {}

#[cfg(any(
    feature = "bign",
    feature = "belt",
    feature = "block",
    feature = "brng"
))]
macro_rules! error {
    ($visibility:vis struct $name:ident { $($struct_field_name:ident: $struct_field_type:ty),* $(,)? } Default { $($struct_init:tt),* $(,)? } $(,)?) => {
        #[derive(Debug)]
        #[allow(dead_code)]
        $visibility struct $name {
            $(
                $visibility $struct_field_name: $struct_field_type
            ),*
            // $($struct_fields)*
        }

        impl $name {
            pub(crate) fn new_box($($struct_field_name: $struct_field_type),*) -> Box<dyn Bee2Error> {
                Box::new(Self {
                    $($struct_init),*
                }) as Box<dyn Bee2Error>
            }
        }

        impl std::fmt::Display for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                std::fmt::Debug::fmt(&self, f)
            }
        }

        impl Error for $name {}
        impl Bee2Error for $name {}
    };
    ($visibility:vis struct $name:ident { $($struct_field_name:ident: $struct_field_type:ty),* } Default { $($struct_init:tt),* } enum $enum_name:ident { $($enum_field:ident $(($($enum_value:ty),*))?,)* } $(,)?) => {
        #[derive(Debug)]
        $visibility enum $enum_name {
            $($enum_field $(($($enum_value),*))?),*
        }
        error!(
            $visibility struct $name {
                kind: $enum_name,
                $($struct_field_name: $struct_field_type),*
            } Default {
                kind,
                $($struct_init),*
            }
        );
    };
}

#[cfg(feature = "bign")]
error!(
    pub struct AnyError {
        error: Box<dyn std::error::Error>,
    },
    Default { error }
);
#[cfg(feature = "belt")]
error!(pub struct InvalidBlockError {}, Default {});
#[cfg(feature = "block")]
error!(
    pub struct InvalidPaddingError {}
    Default {}
    enum InvalidPaddingErrorKind {
        // `data`.
        NoBlocks(Vec<Box<[u8]>>),
        // `data`.
        NoData(Vec<Box<[u8]>>),
        // `data`, `last_block_byte_index`, `padding_byte`, `last_padding_byte`.
        InvalidPaddingData(Vec<Box<[u8]>>, usize, u8, u8),
        // `data`, `block_index`, `block_size`, `len_of_current_block`.
        DifferentBlockSizes(Vec<Box<[u8]>>, usize, u8, u8),
        // `data`, `expected_data_in_last_block`, `last_blocK_len`.
        NotEnoughData(Vec<Box<[u8]>>, u8, u8),
    }
);
#[cfg(feature = "bign")]
error!(
    pub struct BignError {
        code: u32,
    },
    Default { code }
);
#[cfg(feature = "bash")]
error!(
    pub struct BashError {}
    Default {}
    enum BashErrorKind {
        InvalidResistanceLevel,
        HashLengthIsTooLarge,
        CodeError(u32),
    }
);
#[cfg(feature = "brng")]
error!(
    pub struct BrngError {}
    Default {}
    enum BrngErrorKind {
        CodeError(u32),
    }
);
#[cfg(feature = "belt")]
error!(
    pub struct BeltError {}
    Default {}
    enum BeltErrorKind {
        CodeError(u32),
    }
);

pub type Result<T> = core::result::Result<T, Box<dyn Bee2Error>>;
pub type Bee2Result<T> = Result<T>;
