//let us define the util funtions

pub fn ch(x:u32 , y:u32, z:u32) -> u32 {
    (x & y) ^ (!x & z)
}

pub fn maj(x:u32 , y:u32, z:u32) -> u32 {
    (x & y) ^ (x & z) ^ (y & z)
}

pub fn capital_sigma_zero(x:u32) -> u32 {
    x.rotate_right(2) ^ x.rotate_right(13) ^ x.rotate_right(22)
}

pub fn capital_sigma_one(x:u32) -> u32 {
    x.rotate_right(6) ^ x.rotate_right(11) ^ x.rotate_right(25)
}

pub fn sigma_zero(x:u32) -> u32 {
    x.rotate_right(7) ^ x.rotate_right(18) ^ (x>>3)
}

pub fn sigma_one(x:u32) -> u32 {
    x.rotate_right(17) ^ x.rotate_right(19) ^ (x>>10)
}




