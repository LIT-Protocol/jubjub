use ff::Field;
use rand_core::{CryptoRng, RngCore, SeedableRng};
use vsss_rs::FeldmanVerifierSet;

struct TestingRng(rand_xorshift::XorShiftRng);

impl SeedableRng for TestingRng {
    type Seed = <rand_xorshift::XorShiftRng as SeedableRng>::Seed;

    fn from_seed(seed: Self::Seed) -> Self {
        TestingRng(rand_xorshift::XorShiftRng::from_seed(seed))
    }
}

impl RngCore for TestingRng {
    fn next_u32(&mut self) -> u32 {
        self.0.next_u32()
    }

    fn next_u64(&mut self) -> u64 {
        self.0.next_u64()
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.0.fill_bytes(dest)
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.0.try_fill_bytes(dest)
    }
}

impl CryptoRng for TestingRng {}

#[test]
fn test_feldman() {
    let mut rng = TestingRng::from_seed([3u8; 16]);
    let secret_key = jubjub::Scalar::random(&mut rng);
    let (shares, verifiers) = vsss_rs::feldman::split_secret::<jubjub::SubgroupPoint, u8, Vec<u8>>(
        3, 4, secret_key, None, rng,
    )
    .unwrap();
    for share in &shares {
        println!("Share: {:?}", share);
        assert!(verifiers.verify_share(share).is_ok());
    }
}
