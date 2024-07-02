use util::{capital_sigma_one, capital_sigma_zero, sigma_one, sigma_zero, ch, maj};

mod util;

const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

const H0: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

pub struct SHA256 {
    //the i th 256 bit hash value 
    pub h: [u32;8],
    //current 512 bit message block to process 
    buffer: [u32; 16],
    //length of the data processed so far 
    length: usize,
    //words of the message schedule 
    w: [u32;64],
    //eight working variables of 32 bits each 
    temp: [u32;8],
    pub done: bool,
}

fn update_hash(h: &mut[u32;8], w: &mut[u32;64], temp: &mut[u32;8], buffer: &[u32;16]) {
    //w[0..16] = buffer[0..16]
    w[..16].copy_from_slice(&buffer[..]) ;
    //w[16..64] = sigma_one(w_(t-2))+w_(t-7)+sigma_0(w_(t-15))+w_(t-16)
    for i in 16..64 {
        w[i] = sigma_one(w[i-2])
            .wrapping_add(w[i-7])
            .wrapping_add(sigma_zero(w[i-15]))
            .wrapping_add(w[i-16]) ;
    }
    //initialize 8 working variables 
    temp.copy_from_slice(h) ;

    for i in 0..64 {
        let t1 = temp[7]
            .wrapping_add(capital_sigma_one(temp[4]))
            .wrapping_add(ch(temp[4],temp[5],temp[6]))
            .wrapping_add(K[i])
            .wrapping_add(w[i]) ;

        let t2 = capital_sigma_zero(temp[0])
           .wrapping_add(maj(temp[0],temp[1],temp[2])) ;

        temp[7] = temp[6] ;
        temp[6] = temp[5] ;
        temp[5] = temp[4] ;
        temp[4] = temp[3].wrapping_add(t1) ;
        temp[3] = temp[2] ;
        temp[2] = temp[1] ;
        temp[1] = temp[0] ;
        temp[0] = t1.wrapping_add(t2) ;

    }
    //compute the ith intermediate hash value from the i-1 th values 
    for i in 0..8 {
        h[i] = h[i].wrapping_add(temp[i]) ;
    }

}

impl SHA256 {
    pub fn new() -> Self {
        SHA256 {
            h: H0,
            buffer: [0u32; 16],
            length: 0,
            w: [0u32;64],
            temp: [0u32;8],
            done: false,
        }
    }
    pub fn update_hash(&mut self, buffer: &[u32;16]) {
        update_hash(&mut self.h, &mut self.w, &mut self.temp, buffer) ;
        self.length += 512 ;
    }

    //work with the message 
    pub fn process_message(&mut self, data: &[u8]) {
        if data.is_empty() {
            return
        } 
        //offset calculates the number of bytes needed to align self.length to the next multiple of 32 bits
        let offset = ((32-(self.length % 32))>>3) as usize ;
        //buf_ind calculates the index in the buffer corresponding to the current position of self.length
        let mut buf_ind = (((self.length) & 511)>>5) as usize ;
        //take offset amount of data from 'data' iterating over the elements
        for (i,&byte) in data.iter().enumerate().take(offset) {
            self.buffer[buf_ind] ^= (byte as u32)<<((offset-i-1)<<3) ;
        }

        self.length += data.len() << 3 ;

        if offset > data.len() {
            return
        }
        
        if offset > 0 {
            buf_ind += 1 ;
        }

        if data.len() > 3 {
            for i in (offset..(data.len()-3)).step_by(4) {
                if buf_ind & 16 == 16 {
                    update_hash(&mut self.h, &mut self.w, &mut self.temp, &self.buffer) ;
                    buf_ind = 0 ;
                }
                //have to pack each index of buffer with 4 bytes from data 
                self.buffer[buf_ind] = ((data[i] as u32) << 24)
                                      ^((data[i+1] as u32) << 16)
                                      ^((data[i+2] as u32) << 8)
                                      ^(data[i+3] as u32) ;
                buf_ind += 1 ;
            }
        }

        if buf_ind & 16 == 16 {
            update_hash(&mut self.h, &mut self.w, &mut self.temp, &self.buffer) ;
            buf_ind = 0 ;
        }

        self.buffer[buf_ind] = 0 ;
        //This calculates the starting index for the remaining bytes that do not fit into a 4-byte chunk.
        let rem_ind = offset + ((data.len()-offset) & !0b11) ;
        for (i, &byte) in data[rem_ind..].iter().enumerate() {
            self.buffer[buf_ind] ^= (byte as u32) << ((3 - i) << 3);
        }
    }

    pub fn hasher(&mut self)-> [u8;32] {
        //padding
        if !self.done {
            self.done = true ;
            let len = (self.length+8) & 511 ;//adding 8 for the 1 bit to be added in the padding 0x80

            let num = match len.cmp(&448) {
                std::cmp::Ordering::Greater => (448+512-len) >> 3,
                _ => (448-len) >> 3,
            } ; // no of zeros to pad
            let mut padding = vec![0u8; (num + 9) as usize] ;
            let pad_len = padding.len() ;
            padding[0] = 0x80 ; //adding '1' 
            //last 8 bytes for self.length()
            padding[pad_len-8] = (self.length >> 56) as u8 ;
            padding[pad_len-7] = (self.length >> 48) as u8 ;
            padding[pad_len-6] = (self.length >> 40) as u8 ;
            padding[pad_len-5] = (self.length >> 32) as u8 ;
            padding[pad_len-4] = (self.length >> 24) as u8 ;
            padding[pad_len-3] = (self.length >> 16) as u8 ;
            padding[pad_len-2] = (self.length >> 8) as u8 ;
            padding[pad_len-1] = (self.length) as u8 ;

            self.process_message(&padding) ;
        }

        assert_eq!(self.length & 511, 0) ;
        let mut hash_value = [0u8; 32] ;//so take u32;8 to u8;32

        for i in (0..32).step_by(4) {
            hash_value[i] = (self.h[i>>2] >> 24) as u8 ;
            hash_value[i+1] = (self.h[i>>2] >> 16) as u8 ;
            hash_value[i+2] = (self.h[i>>2] >> 8) as u8 ;
            hash_value[i+3] = (self.h[i>>2]) as u8 ;

        }

        hash_value
    }
    
    
}