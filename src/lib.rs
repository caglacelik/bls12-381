use lambdaworks_math::cyclic_group::IsGroup;
use lambdaworks_math::elliptic_curve::short_weierstrass::curves::bls12_381::curve::BLS12381Curve;
use lambdaworks_math::elliptic_curve::short_weierstrass::point::{Endianness, PointFormat};
use lambdaworks_math::elliptic_curve::traits::IsEllipticCurve;
use lambdaworks_math::traits::ByteConversion;
use lambdaworks_math::unsigned_integer::element::U256;

pub fn compute(secret_key: &str) -> String {
    let g = BLS12381Curve::generator();
    let secret_u = U256::from_hex(secret_key).unwrap();
    let public_key = g.operate_with_self(secret_u);
    let pk = public_key.serialize(PointFormat::Projective, Endianness::LittleEndian);
    let pk_hex = U256::from_bytes_be(&pk).unwrap().to_hex().to_lowercase();
    println!("PK: 0x{}", pk_hex);
    pk_hex
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compute() {
        let secret_key = "6C616D6264617370";
        let expected = "efc2d10ad531cebf2b8c7b4325bc93ed91e6477d260304c1f9ecc7ba0e6f5711";
        let result = compute(secret_key);

        assert_eq!(result, expected);
    }

    #[test]
    #[should_panic]
    fn test_compute_invalid_hex() {
        let secret_key = "invalid";

        compute(secret_key);
    }

    #[test]
    #[should_panic]
    fn test_compute_empty_string() {
        let secret_key = "";

        compute(secret_key);
    }
}
