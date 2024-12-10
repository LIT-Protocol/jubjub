use ff::Field;
use group::Group;
use jubjub_plus::Scalar;
use vsss_rs::{shamir, DefaultShare, IdentifierPrimeField, ReadableShareSet, ValuePrimeField};

#[test]
fn dkg_and_refresh() {
    const NODES: usize = 10;
    const THRESHOLD: usize = 6;
    const REFRESHES: usize = 300;
    const REKEYS: usize = 50;

    type JubJubShare = DefaultShare<IdentifierPrimeField<Scalar>, ValuePrimeField<Scalar>>;

    for i in 0..REKEYS {
        let secret_key = IdentifierPrimeField(Scalar::random(&mut rand_core::OsRng));

        let mut shares = shamir::split_secret::<JubJubShare>(
            THRESHOLD,
            NODES,
            &secret_key,
            &mut rand_core::OsRng,
        )
        .unwrap();

        let res = (&shares[..THRESHOLD]).combine();
        assert!(res.is_ok(), "{:?}", res.unwrap_err());
        assert_eq!(res.unwrap(), secret_key);

        let zero_secret = IdentifierPrimeField(Scalar::zero());
        for j in 0..REFRESHES {
            let zero_shares = shamir::split_secret::<JubJubShare>(
                THRESHOLD,
                NODES,
                &zero_secret,
                &mut rand_core::OsRng,
            )
            .unwrap();
            let mut cloned_shares = shares.clone();
            for (share, zero_share) in cloned_shares.iter_mut().zip(zero_shares.iter()) {
                assert_eq!(share.identifier.0, zero_share.identifier.0);
                share.value.0 += zero_share.value.0;
            }

            let res = (&cloned_shares[..THRESHOLD]).combine();
            assert!(
                res.is_ok(),
                "rekey {} refresh {} failed, {:?}",
                i + 1,
                j + 1,
                res.unwrap_err()
            );
            let new_secret = res.unwrap();
            assert_eq!(
                new_secret,
                secret_key,
                "rekey {} refresh {} failed, expected: {}, got: {}",
                i + 1,
                j + 1,
                hex::encode(secret_key.0.to_bytes()),
                hex::encode(new_secret.0.to_bytes())
            );
            shares = cloned_shares;
        }
    }
}
