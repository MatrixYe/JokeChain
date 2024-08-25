/// @Name signature
///
/// @Date 2024/8/15 下午2:26
///
/// @Author Matrix.Ye
///
/// @Description:
///
///
///
use k256::ecdsa::{Signature, signature::Signer, signature::Verifier, SigningKey, VerifyingKey};
use k256::elliptic_curve::rand_core::OsRng;

// 随机生成一个私钥
pub fn new_private_key_random() -> SigningKey {
    SigningKey::random(&mut OsRng)
}

// 生成一个私钥通过hex字符串
pub fn new_private_key_by_str(hex_key: &str) -> Result<SigningKey, k256::elliptic_curve::Error> {
    todo!()
}

// 使用私钥对消息进行签名
pub fn sign(signing_key: &SigningKey, message: &[u8]) -> Signature {
    signing_key.sign(message)
}

// 使用公钥对签名进行验证
pub fn verify(verifying_key: &VerifyingKey, message: &[u8], signature: &Signature) -> bool {
    verifying_key.verify(message, signature).is_ok()
}

// 获取公钥
pub fn get_pubkey(signing_key: &SigningKey) -> VerifyingKey {
    VerifyingKey::from(signing_key)
}

// 单元测试
#[cfg(test)]
mod tests {
    use super::{get_pubkey, new_private_key_random, sign, verify};

    #[test]
    fn test_crypto_sign_and_verify() {
        // 用户A生成一套密钥对
        let message = b"Hello, Bitcoin!";
        let private_key_a = new_private_key_random();
        let public_key_a = get_pubkey(&private_key_a);

        // 用A的私钥对消息进行签名
        let signature = sign(&private_key_a, message);

        // 用A的公钥对消息和签名进行验证
        let is_valid = verify(&public_key_a, message, &signature);
        println!("{:?}", is_valid);

        assert!(is_valid, "签名验证失败");
    }

    #[test]
    fn test_crypto_invalid_signature() {
        // 用户A生成一套密钥对
        let message = b"Hello, Bitcoin!";
        let private_key_a = new_private_key_random();
        let public_key_a = get_pubkey(&private_key_a);

        // 用户B生成一套密钥对
        let private_key_b = new_private_key_random();
        let public_key_b = get_pubkey(&private_key_b);

        // 用A的私钥对消息进行签名
        let signature = sign(&private_key_a, message);

        // 用B的公钥对消息和签名进行验证
        let is_valid = verify(&public_key_b, message, &signature);
        println!("{:?}", is_valid);

        assert!(!is_valid, "不应通过签名验证");
    }
}