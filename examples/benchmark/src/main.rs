use bee2_rs::belt::{BeltEncryptionAlgorithm, BeltKey128};
use std::env;

fn crypto_things(input_bytes: &[u8], key: &BeltKey128, iv: [u8; 16], last: bool) {
    let mut cbc_ctx = key.clone().cbc(iv);
    let ciphertext = cbc_ctx.encrypt(input_bytes);

    if last {
        println!("{ciphertext:?}");
    }

    let mut cbc_ctx = key.clone().cbc(iv);
    let decrypted_plaintext = cbc_ctx.decrypt(ciphertext).unwrap();

    if *input_bytes != *decrypted_plaintext {
        panic!("SOMETHING WENT CATASTROPHICALLY WRONG!!!!!!!!!!!!!!");
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        panic!("There should be an argument (single one) you dumbass!");
    }
    let max_n: usize = match args[1].parse() {
        Ok(value) => value,
        Err(_err) => {
            panic!("It's not a number!");
        }
    };
    // let input = "Hello, World! This is a test.";
    // let input_bytes = input.as_bytes();
    // println!("{input_bytes:?}");
    let input_bytes = &[72, 101, 108, 108, 111, 44, 32, 87, 111, 114, 108, 100, 33, 32, 84, 104, 105, 115, 32, 105, 115, 32, 97, 32, 116, 101, 115, 116, 46, 0, 0, 0];
    let key = bee2_rs::belt::BeltKey128::new([16; 16]);
    let iv = [16; 16];
    for i in 0..max_n - 1 {
        crypto_things(input_bytes, &key, iv, false);
    }
    crypto_things(input_bytes, &key, iv, true);
}
