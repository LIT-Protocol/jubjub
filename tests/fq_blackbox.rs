mod common;

use ff::Field;
use common::{new_rng, MyRandom, NUM_BLACK_BOX_CHECKS};
use jubjub_plus::*;

#[test]
fn test_to_and_from_bytes() {
    let mut rng = new_rng();
    for _ in 0..NUM_BLACK_BOX_CHECKS {
        let a = Fq::random(&mut rng);
        assert_eq!(a, Fq::from_le_bytes(&Fq::to_le_bytes(&a)).unwrap());
    }
}

#[test]
fn test_additive_associativity() {
    let mut rng = new_rng();
    for _ in 0..NUM_BLACK_BOX_CHECKS {
        let a = Fq::random(&mut rng);
        let b = Fq::random(&mut rng);
        let c = Fq::random(&mut rng);
        assert_eq!((a + b) + c, a + (b + c))
    }
}

#[test]
fn test_additive_identity() {
    let mut rng = new_rng();
    for _ in 0..NUM_BLACK_BOX_CHECKS {
        let a = Fq::random(&mut rng);
        assert_eq!(a, a + Fq::ZERO);
        assert_eq!(a, Fq::ZERO + a);
    }
}

#[test]
fn test_subtract_additive_identity() {
    let mut rng = new_rng();
    for _ in 0..NUM_BLACK_BOX_CHECKS {
        let a = Fq::random(&mut rng);
        assert_eq!(a, a - Fq::ZERO);
        assert_eq!(a, Fq::ZERO - -&a);
    }
}

#[test]
fn test_additive_inverse() {
    let mut rng = new_rng();
    for _ in 0..NUM_BLACK_BOX_CHECKS {
        let a = Fq::random(&mut rng);
        let a_neg = -&a;
        assert_eq!(Fq::ZERO, a + a_neg);
        assert_eq!(Fq::ZERO, a_neg + a);
    }
}

#[allow(clippy::eq_op)]
#[test]
fn test_additive_commutativity() {
    let mut rng = new_rng();
    for _ in 0..NUM_BLACK_BOX_CHECKS {
        let a = Fq::random(&mut rng);
        let b = Fq::random(&mut rng);
        assert_eq!(a + b, b + a);
    }
}

#[test]
fn test_multiplicative_associativity() {
    let mut rng = new_rng();
    for _ in 0..NUM_BLACK_BOX_CHECKS {
        let a = Fq::random(&mut rng);
        let b = Fq::random(&mut rng);
        let c = Fq::random(&mut rng);
        assert_eq!((a * b) * c, a * (b * c))
    }
}

#[test]
fn test_multiplicative_identity() {
    let mut rng = new_rng();
    for _ in 0..NUM_BLACK_BOX_CHECKS {
        let a = Fq::random(&mut rng);
        assert_eq!(a, a * Fq::ONE);
        assert_eq!(a, Fq::ONE * a);
    }
}

#[test]
fn test_multiplicative_inverse() {
    let mut rng = new_rng();
    for _ in 0..NUM_BLACK_BOX_CHECKS {
        let a = Fq::random(&mut rng);
        if a == Fq::ZERO {
            continue;
        }
        let a_inv = a.invert().unwrap();
        assert_eq!(Fq::ONE, a * a_inv);
        assert_eq!(Fq::ONE, a_inv * a);
    }
}

#[test]
fn test_multiplicative_commutativity() {
    let mut rng = new_rng();
    for _ in 0..NUM_BLACK_BOX_CHECKS {
        let a = Fq::random(&mut rng);
        let b = Fq::random(&mut rng);
        assert_eq!(a * b, b * a);
    }
}

#[test]
fn test_multiply_additive_identity() {
    let mut rng = new_rng();
    for _ in 0..NUM_BLACK_BOX_CHECKS {
        let a = Fq::random(&mut rng);
        assert_eq!(Fq::ZERO, Fq::ZERO * a);
        assert_eq!(Fq::ZERO, a * Fq::ZERO);
    }
}
