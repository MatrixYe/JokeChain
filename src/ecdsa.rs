use std::ops::{Add, Sub};

use num_bigint::{BigUint, RandBigInt, ToBigUint};
use num_traits::{FromPrimitive, Num, One, Zero};
use rand::Rng;
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, PartialEq)]
pub struct Point {
    x: BigUint,
    y: BigUint,
}
impl Point {
    /// 定义零点 (0, 0) 用于运算
    fn zero() -> Point {
        Point {
            x: BigUint::zero(),
            y: BigUint::zero(),
        }
    }
}
pub struct Secp256k1 {
    a: BigUint,
    b: BigUint,
    n: BigUint,
}
#[derive(Debug, Clone)]
pub struct Signature {
    r: BigUint,
    s: BigUint,
}
const N: &str = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F";
const G_X: &str = "79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798";
const G_Y: &str = "483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8";

impl Secp256k1 {
    /// 创建比特币的secp256k1椭圆曲线
    fn new() -> Secp256k1 {
        Secp256k1 {
            a: BigUint::zero(),
            b: BigUint::from_u64(7).unwrap(),
            n: BigUint::from_str_radix(N, 16).unwrap(),
        }
    }

    /// 获取基点G
    fn g() -> Point {
        let g_x = BigUint::from_str_radix(G_X, 16).unwrap();
        let g_y = BigUint::from_str_radix(G_Y, 16).unwrap();
        Point { x: g_x, y: g_y }
    }

    /// 点加法
    fn add(&self, p: &Point, q: &Point) -> Point {
        if *p == Point::zero() {
            return q.clone();
        }
        if *q == Point::zero() {
            return p.clone();
        }

        let s: BigUint;
        if p == q {
            // 当 P == Q 时，使用切线法计算斜率
            let numerator = (BigUint::from(3u32) * &p.x * &p.x + &self.a) % &self.n;
            let denominator = (BigUint::from(2u32) * &p.y) % &self.n;
            if denominator == BigUint::zero() {
                return Point::zero(); // 无法定义斜率，返回零点
            }
            s = (numerator * mod_inverse(denominator, &self.n)) % &self.n;
        } else {
            // 当 P != Q 时，使用割线法计算斜率
            let numerator = (&q.y + &self.n - &p.y) % &self.n;
            let denominator = (&q.x + &self.n - &p.x) % &self.n;
            if denominator == BigUint::zero() {
                return Point::zero(); // 垂直线情况
            }
            s = (numerator * mod_inverse(denominator, &self.n)) % &self.n;
        }

        // 计算新的点 R 的坐标
        let x_r = (&s * &s + &self.n - &p.x - &q.x) % &self.n;
        let y_r = (&s * (&p.x + &self.n - &x_r) + &self.n - &p.y) % &self.n;

        Point { x: x_r, y: y_r }
    }

    /// 标量乘法
    fn mul(&self, p: &Point, mut k: BigUint) -> Point {
        let mut result = Point::zero();
        let mut addend = p.clone();

        while k > BigUint::zero() {
            if &k % BigUint::from(2u32) == BigUint::one() {
                result = self.add(&result, &addend);
            }
            addend = self.add(&addend, &addend);
            k >>= 1;
        }

        result
    }

    /// 获取一个在 [1, n-1] 范围内的随机数
    fn get_random_k(&self) -> BigUint {
        let mut rng = OsRng; // 安全的随机数生成器
        let k = rng.gen_biguint_range(&1.to_biguint().unwrap(), &self.n);
        k
    }

    /// 获取一个数据的哈希值，并确保哈希值小于 n
    fn hash_message(&self, message: &[u8]) -> BigUint {
        let mut hasher = Sha256::new();
        hasher.update(message);
        let hash_result = hasher.finalize();

        // 将哈希值转化为BigUint
        let mut hash_value = BigUint::from_bytes_be(&hash_result);

        // 如果哈希值大于n，则裁剪
        if hash_value >= self.n {
            hash_value = hash_value % &self.n;
        }

        hash_value
    }

    /// 签名方法，输入私钥和消息摘要，返回签名 (r, s)
    fn sign(&self, private_key: &BigUint, msg_hash: &BigUint) -> Signature {
        loop {
            // Step 1: 随机生成 k，范围在 [1, n-1] 内
            let k = self.get_random_k();

            // Step 2: 计算 Q = k * G
            let q = self.mul(&Secp256k1::g(), k.clone());

            // Step 3: 取 Q 的 x 坐标作为 r，如果 r == 0 则重新选择 k
            let r = q.x % &self.n;
            if r == BigUint::zero() {
                continue;
            }

            // Step 4: 计算 s = k^{-1} * (z + r * d) mod n
            let k_inv = mod_inverse(k, &self.n);
            let s = (k_inv * (msg_hash + &r * private_key)) % &self.n;
            if s == BigUint::zero() {
                continue;
            }

            return Signature { r, s };
        }
    }
    /// 签名的验证
    fn verify(&self, signature: &Signature, msg_hash: &BigUint, public_key: &Point) -> bool {
        // 验证 r 和 s 是否在有效范围内
        if signature.r <= BigUint::zero() || signature.r >= self.n {
            return false;
        }
        if signature.s <= BigUint::zero() || signature.s >= self.n {
            return false;
        }

        // 计算 w = s^{-1} mod n
        let w = mod_inverse(signature.s.clone(), &self.n);

        // 计算 u1 = msg_hash * w mod n 和 u2 = r * w mod n
        let u1 = (msg_hash * &w) % &self.n;
        let u2 = (&signature.r * &w) % &self.n;

        // 计算 P = u1 * G + u2 * Q
        let g = Secp256k1::g();
        let p1 = self.mul(&g, u1);
        let p2 = self.mul(public_key, u2);
        let p = self.add(&p1, &p2);

        let r_calculated = p.x % &self.n;

        println!("signature.r = {:?}", signature.r);
        println!("r_calculated = {:?}", r_calculated);

        // 验证 P 的 x 坐标是否等于签名中的 r
        r_calculated == signature.r
    }
}


/// 扩展欧几里得算法计算模逆
fn mod_inverse(value: BigUint, modulo: &BigUint) -> BigUint {
    let mut t = BigUint::zero();
    let mut new_t = BigUint::one();
    let mut r = modulo.clone();
    let mut new_r = value.clone();

    while new_r != BigUint::zero() {
        let quotient = &r / &new_r;

        let temp_t = t.clone();
        t = new_t.clone();
        new_t = (&temp_t + modulo - (&quotient * &new_t) % modulo) % modulo;

        let temp_r = r.clone();
        r = new_r.clone();
        new_r = &temp_r - &quotient * &new_r;
    }

    if r > BigUint::one() {
        panic!("The value and the modulo are not co-prime, so no modular inverse exists");
    }

    t
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_point_add() {
        let curve = Secp256k1::new();
        let g = Secp256k1::g();

        // 测试加法 G + G
        let result = curve.add(&g, &g);
        println!("G + G = {:?}", result);
    }

    #[test]
    fn test_point_mul() {
        let curve = Secp256k1::new();
        let g = Secp256k1::g();

        // 测试标量乘法 2 * G
        let result = curve.mul(&g, BigUint::from_u64(2).unwrap());
        // assert_eq!()
        println!("2 * G = {:?}", result);
    }
    #[test]
    fn test_point_add_mul() {
        let curve = Secp256k1::new();
        let g = Secp256k1::g();

        // 测试加法 G + G
        let result1 = curve.add(&g, &g);
        let result2 = curve.mul(&g, BigUint::from(2u32));

        println!("G + G = {:?}", result1);
        println!("G * 2 = {:?}", result2);
        assert_eq!(result1, result2)
    }

    #[test]
    fn test_gen_random_k() {
        let curve = Secp256k1::new();
        let k = curve.get_random_k();
        println!("{}", k);
    }
    #[test]
    fn test_hash_message() {
        let curve = Secp256k1::new();
        let message = b"Hello, world!";
        let hash_value = curve.hash_message(message);
        assert!(hash_value < curve.n);
        println!("Hash value: {:?}", hash_value);
    }

    #[test]
    fn test_sign() {
        let curve = Secp256k1::new();
        let private_key = BigUint::from(111u32);
        let msg = b"Hello, Bitcoin!";
        let msg_hash = curve.hash_message(msg);

        // 签名
        let signature = curve.sign(&private_key, &msg_hash);
        println!("Signature: r = {:?}, s = {:?}", signature.r, signature.s);
    }

    #[test]
    fn test_sign_and_verify() {
        let curve = Secp256k1::new();

        // 生成随机私钥并计算对应的公钥
        let private_key = BigUint::from(111u32);
        let public_key = curve.mul(&Secp256k1::g(), private_key.clone());
        println!("private_key {:?}", private_key);
        println!("public_key {:?}", public_key);
        // 计算消息摘要
        let message = b"Hello, Bitcoin!";
        let msg_hash = curve.hash_message(message);
        println!("message{:?}", message);
        // 签名
        let signature = curve.sign(&private_key, &msg_hash);
        println!("signature{:?}", signature);

        // 验证签名
        let is_valid = curve.verify(&signature, &msg_hash, &public_key);
        assert!(is_valid, "Signature verification failed!");
    }

    #[test]
    fn test_invalid_signature() {
        let curve = Secp256k1::new();

        // 生成随机私钥并计算对应的公钥
        // let private_key = curve.get_random_k();
        let private_key = BigUint::from_str_radix("40121828775096451297723744859055496860799148363974524184949683262927962615227", 10).unwrap();
        let public_key = curve.mul(&Secp256k1::g(), private_key.clone());

        // 计算消息摘要
        let message = b"Hello, Bitcoin!";
        let msg_hash = curve.hash_message(message);

        // 签名
        let signature = curve.sign(&private_key, &msg_hash);

        // 修改签名，模拟错误的签名
        let mut invalid_signature = signature.clone();
        invalid_signature.r += BigUint::one(); // 修改签名的 r 值

        // 验证签名
        let is_valid = curve.verify(&invalid_signature, &msg_hash, &public_key);
        assert!(!is_valid, "Invalid signature should not be verified!");
    }
}
