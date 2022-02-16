use aes::{Aes128, Block, ParBlocks};
use aes::cipher::{
    BlockCipher, BlockEncrypt, BlockDecrypt, NewBlockCipher,
    generic_array::GenericArray,
};
use std::convert::TryInto;
use std::time::Instant;
use wasm_bindgen::prelude::*;
use web_sys::console;
use salsa20::{Salsa20, Key, Nonce};
use salsa20::cipher::{NewCipher, StreamCipher, StreamCipherSeek};
use js_sys::Uint8Array;

extern crate console_error_panic_hook;
use std::panic;

#[wasm_bindgen]
pub fn main(){
    let roundCount = 100000;

    // AES bench
    let key = GenericArray::from_slice(&[0u8; 16]);
    let mut block = Block::default();
    let mut block8 = ParBlocks::default();
    //Initialize cipher
    let cipher = Aes128::new(&key);
    let block_copy = block.clone();

    console::log_1(&"Start AES".into());
    for i in 0..roundCount{
        // Encrypt block in-place
        cipher.encrypt_block(&mut block);   
    }
    console::log_1(&"End AES".into());

    // Rust's Salsa bench
    let mut data: [u8; 16] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
    let key = Key::from_slice(b"an example very very secret key.");
    let nonce = Nonce::from_slice(b"a nonce.");
    // create cipher instance
    let mut cipher = Salsa20::new(&key, &nonce);
    console::log_1(&"Start Rust Salsa".into());
    for i in 0..roundCount{
        cipher.apply_keystream(&mut data);
    }
    console::log_1(&"End Rust Salsa".into());

    // ported tweetnacl's Salsa bench
    console::log_1(&"Start ported Salsa".into());
    let mut o: [u32; 16] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
    let mut p: [u32; 16] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
    let c: [u32; 16] = [101, 120, 112, 97, 110, 100, 32, 51, 50, 45, 98,
    121, 116, 101, 32, 107];
    let k: [u32; 32] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14,
    15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 0, 0, 0, 0];

    for i in 0..roundCount{
        salsa(&mut o, &p, &k, &c);
        p = o;
    }
    console::log_1(&"End ported Salsa".into());
    console::log_1(&"First bytes of ported Salsa output:".into());
    console::log_1(&o[0].into());
    console::log_1(&o[1].into());
    console::log_1(&o[2].into());
    console::log_1(&o[3].into());
    console::log_1(&o[4].into());
}


pub fn salsa(o: &mut [u32], p: &[u32], k: &[u32], c: &[u32]) {
        let j0  = c[ 0] | c[1] << 8 | c[ 2] << 16 | c[ 3] << 24;
        let j1  = k[ 0] | k[ 1] << 8 | k[ 2] << 16 | k[ 3] << 24;
        let j2  = k[ 4] | k[ 5] << 8 | k[ 6] << 16 | k[ 7] << 24;
        let j3  = k[ 8] | k[ 9] << 8 | k[10] << 16 | k[11] << 24;
        let j4  = k[12] | k[13] << 8 | k[14] << 16 | k[15] << 24;
        let j5  = c[ 4] | c[ 5] << 8 | c[ 6] << 16 | c[ 7] << 24;
        let j6  = p[ 0] | p[ 1] << 8 | p[ 2] << 16 | p[ 3] << 24;
        let j7  = p[ 4] | p[ 5] << 8 | p[ 6] << 16 | p[ 7] << 24;
        let j8  = p[ 8] | p[ 9] << 8 | p[10] << 16 | p[11] << 24;
        let j9  = p[12] | p[13] << 8 | p[14] << 16 | p[15] << 24;
        let j10 = c[ 8] | c[ 9] << 8 | c[10] << 16 | c[11] << 24;
        let j11 = k[16] | k[17] << 8 | k[18] << 16 | k[19] << 24;
        let j12 = k[20] | k[21] << 8 | k[22] << 16 | k[23] << 24;
        let j13 = k[24] | k[25] << 8 | k[26] << 16 | k[27] << 24;
        let j14 = k[28] | k[29] << 8 | k[30] << 16 | k[31] << 24;
        let j15 = c[12] | c[13] << 8 | c[14] << 16 | c[15] << 24;
      
        let mut x0 = j0;
        let mut x1 = j1;
        let mut x2 = j2;
        let mut x3 = j3;
        let mut x4 = j4;
        let mut x5 = j5;
        let mut x6 = j6; 
        let mut x7 = j7;
        let mut x8 = j8;
        let mut x9 = j9 ;
        let mut x10 = j10; 
        let mut x11 = j11; 
        let mut x12 = j12 ;
        let mut x13 = j13 ;
        let mut x14 = j14;
        let mut x15 = j15 ;
        let mut u;
          
        let mut i = 0;
        while i < 20 {
          u = x0 + x12 | 0;
          x4 ^= u << 7 | u >> (32-7);
          u = x4 + x0 | 0;
          x8 ^= u << 9 | u >> (32-9);
          u = x8 + x4 | 0;
          x12 ^= u << 13 | u >> (32-13);
          u = x12 + x8 | 0;
          x0 ^= u << 18 | u >> (32-18);
      
          u = x5 + x1 | 0;
          x9 ^= u << 7 | u >> (32-7);
          u = x9 + x5 | 0;
          x13 ^=  u << 9 | u >> (32-9);
          u = x13 + x9 | 0;
          x1 ^= u << 13 | u >> (32-13);
          u = x1 + x13 | 0;
          x5 ^= u << 18 | u >> (32-18);
      
          u = x10 + x6 | 0;
          x14 ^= u << 7 | u >> (32-7);
          u = x14 + x10 | 0;
          x2 ^=  u << 9| u >> (32-9);
          u = x2 + x14 | 0;
          x6 ^= u << 13| u >> (32-13);
          u = x6 + x2 | 0;
          x10 ^= u << 18 | u >> (32-18);
      
          u = x15 + x11 | 0;
          x3 ^= u << 7 | u >> (32-7);
          u = x3 + x15 | 0;
          x7 ^=  u << 9 | u >> (32-9);
          u = x7 + x3 | 0;
          x11 ^=u << 13 | u >> (32-13);
          u = x11 + x7 | 0;
          x15 ^= u << 18 | u >> (32-18);
      
          u = x0 + x3 | 0;
          x1 ^= u << 7 | u >> (32-7);
          u = x1 + x0 | 0;
          x2 ^=  u << 9 | u >> (32-9);
          u = x2 + x1 | 0;
          x3 ^= u << 13 | u >> (32-13);
          u = x3 + x2 | 0;
          x0 ^= u << 18 | u >> (32-18);
      
          u = x5 + x4 | 0;
          x6 ^= u << 7 | u >> (32-7);
          u = x6 + x5 | 0;
          x7 ^=  u << 9 | u >> (32-9);
          u = x7 + x6 | 0;
          x4 ^= u << 13 | u >> (32-13);
          u = x4 + x7 | 0;
          x5 ^= u << 18 | u >> (32-18);
      
          u = x10 + x9 | 0;
          x11 ^= u << 7 | u >> (32-7);
          u = x11 + x10 | 0;
          x8 ^=  u << 9 | u >> (32-9);
          u = x8 + x11 | 0;
          x9 ^= u << 13 | u >> (32-13);
          u = x9 + x8 | 0;
          x10 ^= u << 18 | u >> (32-18);
      
          u = x15 + x14 | 0;
          x12 ^= u << 7 | u >> (32-7);
          u = x12 + x15 | 0;
          x13 ^=  u << 9 | u >> (32-9);
          u = x13 + x12 | 0;
          x14 ^= u << 13 | u >> (32-13);
          u = x14 + x13 | 0;
          x15 ^= u << 18 | u >> (32-18);

          i +=2
        }
        x0 =  x0 +  j0 | 0;
        x1 =  x1 +  j1 | 0;
        x2 =  x2 +  j2 | 0;
        x3 =  x3 +  j3 | 0;
        x4 =  x4 +  j4 | 0;
        x5 =  x5 +  j5 | 0;
        x6 =  x6 +  j6 | 0;
        x7 =  x7 +  j7 | 0;
        x8 =  x8 +  j8 | 0;
        x9 =  x9 +  j9 | 0;
        x10 = x10 + j10 | 0;
        x11 = x11 + j11 | 0;
        x12 = x12 + j12 | 0;
        x13 = x13 + j13 | 0;
        x14 = x14 + j14 | 0;
        x15 = x15 + j15 | 0;
      
        o[ 0] = x0 >>  0 & 0xff;
        o[ 1] = x0 >>  8 & 0xff;
        o[ 2] = x0 >> 16 & 0xff;
        o[ 3] = x0 >> 24 & 0xff;
      
        o[ 4] = x1 >>  0 & 0xff;
        o[ 5] = x1 >>  8 & 0xff;
        o[ 6] = x1 >> 16 & 0xff;
        o[ 7] = x1 >> 24 & 0xff;
      
        o[ 8] = x2 >>  0 & 0xff;
        o[ 9] = x2 >>  8 & 0xff;
        o[10] = x2 >> 16 & 0xff;
        o[11] = x2 >> 24 & 0xff;
      
        o[12] = x3 >>  0 & 0xff;
        o[13] = x3 >>  8 & 0xff;
        o[14] = x3 >> 16 & 0xff;
        o[15] = x3 >> 24 & 0xff;
        // we only need 16 bytes of the output
}