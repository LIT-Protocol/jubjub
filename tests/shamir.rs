use ff::Field;
use jubjub_plus::{Scalar, SubgroupPoint};
use rand_core::{CryptoRng, RngCore, SeedableRng};
use vsss_rs::{
    DefaultShare, FeldmanVerifierSet, IdentifierPrimeField, ValueGroup, ValuePrimeField,
};

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
    type SecretShare = DefaultShare<IdentifierPrimeField<Scalar>, ValuePrimeField<Scalar>>;
    type JubjubVerifier = ValueGroup<SubgroupPoint>;

    let mut rng = TestingRng::from_seed([3u8; 16]);
    let secret_key = IdentifierPrimeField(Scalar::random(&mut rng));
    let (shares, verifiers) =
        vsss_rs::feldman::split_secret::<SecretShare, JubjubVerifier>(3, 4, &secret_key, None, rng)
            .unwrap();
    for share in &shares {
        println!("Share: {:?}", share);
        assert!(verifiers.verify_share(share).is_ok());
    }
}
