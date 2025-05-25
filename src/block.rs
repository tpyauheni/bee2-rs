use crate::errors::{Bee2Result, InvalidPaddingError, InvalidPaddingErrorKind};

pub struct Block {}

impl Block {
    pub fn pad(data: &[u8], block_size: u8) -> Vec<Box<[u8]>> {
        let mut blocks: Vec<Box<[u8]>> = data
            .chunks(block_size as usize)
            .take(data.len() / block_size as usize)
            .map(Box::from)
            .collect();
        let last_block_offset = data.len() / block_size as usize * block_size as usize;
        let last_block = &data[last_block_offset..];
        let unpadded_size = last_block.len() as u8;
        let padding_size = block_size - unpadded_size;
        let mut last_block_padded = last_block.to_vec();
        last_block_padded.extend(vec![unpadded_size; padding_size as usize]);
        blocks.push(last_block_padded.into_boxed_slice());
        blocks
    }

    pub fn unpad(data: Vec<Box<[u8]>>) -> Bee2Result<Box<[u8]>> {
        let Some((last_block, block_size)) = data.last().map(|value| (value, value.len())) else {
            return Err(InvalidPaddingError::new_box(InvalidPaddingErrorKind::NoBlocks(data)));
        };

        let Some(&last_block_size) = last_block.last() else {
            return Err(InvalidPaddingError::new_box(InvalidPaddingErrorKind::NoData(data)));
        };

        if last_block_size as usize >= last_block.len() {
            return Err(InvalidPaddingError::new_box(InvalidPaddingErrorKind::NotEnoughData(data.clone(), last_block_size, last_block.len() as u8)));
        }

        let mut last_data_chunk: Vec<u8> = vec![];

        for (i, byte) in last_block.iter().enumerate() {
            if (i as u8) < last_block_size {
                last_data_chunk.push(*byte);
            } else if *byte != last_block_size {
                return Err(InvalidPaddingError::new_box(InvalidPaddingErrorKind::InvalidPaddingData(data.clone(), i, *byte, last_block_size)));
            }
        }

        let mut result_data: Vec<u8> = vec![];

        for (i, block) in data.iter().take(data.len() - 1).enumerate() {
            if block_size != block.len() {
                return Err(InvalidPaddingError::new_box(InvalidPaddingErrorKind::DifferentBlockSizes(data.clone(), i, block_size as u8, block.len() as u8)));
            }
            result_data.extend(block);
        }

        result_data.extend(last_data_chunk);

        Ok(result_data.into_boxed_slice())
    }

    pub fn is_padding_correct(data: Vec<Box<[u8]>>) -> bool {
        let Some((last_block, block_size)) = data.last().map(|value| (value, value.len())) else {
            return false;
        };

        let Some(&last_block_size) = last_block.last() else {
            return false;
        };

        if last_block_size as usize >= last_block.len() {
            return false;
        }

        for byte in &last_block[last_block_size as usize..] {
            if *byte != last_block_size {
                return false;
            }
        }

        for block in data.iter().take(data.len() - 1) {
            if block_size != block.len() {
                return false;
            }
        }

        true
    }
}

#[cfg(test)]
mod tests {
    use super::Block;

    #[test]
    fn test_multiple_data_sizes_16() {
        for i in 0..200 {
            let data = vec![255; i];
            let padded = Block::pad(&data, 16);
            assert!(Block::is_padding_correct(padded.clone()));
            let unpadded = Block::unpad(padded).unwrap();
            assert_eq!(*data, *unpadded);
        }
    }

    #[test]
    fn test_multiple_data_sizes_32() {
        for i in 0..200 {
            let data = vec![255; i];
            let padded = Block::pad(&data, 32);
            assert!(Block::is_padding_correct(padded.clone()));
            let unpadded = Block::unpad(padded).unwrap();
            assert_eq!(*data, *unpadded);
        }
    }

    #[test]
    fn test_various_bs_and_sizes() {
        for block_size in 1..50 {
            for data_size in 0..=2 * block_size + 5 {
                let mut data = vec![];

                for i in 0..data_size {
                    data.push(i);
                }

                let padded = Block::pad(&data, block_size);
                assert!(Block::is_padding_correct(padded.clone()));
                let unpadded = Block::unpad(padded).unwrap();
                assert_eq!(*data, *unpadded);
            }
        }
    }

    #[test]
    fn test_invalid_padding_16() {
        for data_size in 0..200 {
            let mut data = vec![];

            for i in 0..data_size {
                data.push(i);
            }

            let mut blocks: Vec<Box<[u8]>> = data
                .chunks(16)
                .take(data.len() / 16)
                .map(Box::from)
                .collect();
            let last_block_offset = data.len() / 16 * 16;
            let last_block = &data[last_block_offset..];
            blocks.push(Box::from(last_block));

            if data_size > 0 && data_size < 16 {
                assert!(Block::is_padding_correct(blocks.clone()));
                assert!(Block::unpad(blocks).is_ok());
            } else {
                assert!(!Block::is_padding_correct(blocks.clone()));
                assert!(Block::unpad(blocks).is_err());
            }
        }
    }
}
