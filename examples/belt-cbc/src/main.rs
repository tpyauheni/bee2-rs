use bee2_rs::belt::BeltEncryptionAlgorithm;

fn to_string(bytes: &[u8]) -> String {
    if let Ok(string) = String::from_utf8(bytes.to_vec()) {
        format!("txt:{string:?}")
    } else {
        format!("hex:\"{}\"", hex::encode(bytes))
    }
}

fn main() {
    loop {
        let mut input = String::new();

        println!("Enter a message:");
        if let Err(err) = std::io::stdin().read_line(&mut input) {
            eprintln!("Line read error: {err}");
        }

        let input_bytes = if input.starts_with("txt:") {
            input.as_bytes()[4..].to_vec()
        } else if input.starts_with("hex:") {
            if let Ok(data) = hex::decode(&input[4..input.len() - 1]) {
                data
            } else {
                input.as_bytes().to_vec()
            }
        } else if input.starts_with("quit:") {
            break;
        } else {
            input.as_bytes().to_vec()
        };

        let key = bee2_rs::belt::BeltKey128::new([16; 16]);
        let mut cbc_ctx = key.clone().cbc([16; 16]);
        let ciphertext = cbc_ctx.encrypt(&input_bytes);
        let fmt_ciphertext = to_string(&ciphertext);
        println!("Encrypted to {fmt_ciphertext}");

        let mut cbc_ctx = key.cbc([16; 16]);
        let decrypted_plaintext = match cbc_ctx.decrypt(ciphertext) {
            Ok(decrypted_plaintext) => decrypted_plaintext,
            Err(err) => {
                eprintln!("Failed to decrypt plaintext: {err}");
                continue;
            }
        };
        let fmt_plaintext = to_string(&decrypted_plaintext);
        println!("Decrypted to {fmt_plaintext}");

        if *input_bytes != *decrypted_plaintext {
            eprintln!("[!!!] DECRYPTED PLAINTEXT MISMATCH DETECTED. THIS IS A BUG!");
        }
    }
}
