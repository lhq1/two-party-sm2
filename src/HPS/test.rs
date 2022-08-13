use super::*;
use curv::arithmetic::Converter;
use curv::BigInt;

#[test]
fn test_d_log_proof_party_two_party_one() {
    let (party_one_first_message, comm_witness, _ec_key_pair_party1) =
        party_one::KeyGenFirstMsg::create_commitments();
    let (party_two_first_message, _ec_key_pair_party2) = party_two::KeyGenFirstMsg::create();
    let party_one_second_message = party_one::KeyGenSecondMsg::verify_and_decommit(
        comm_witness,
        &party_two_first_message.d_log_proof,
    )
    .expect("failed to verify and decommit");

    let _party_two_second_message = party_two::KeyGenSecondMsg::verify_commitments_and_dlog_proof(
        &party_one_first_message,
        &party_one_second_message,
    )
    .expect("failed to verify commitments and DLog proof");
}

#[test]
fn test_full_key_gen(){
    let (party_one_first_message, comm_witness, _ec_key_pair_party1) =
        party_one::KeyGenFirstMsg::create_commitments();
    let (party_two_first_message, _ec_key_pair_party2) = party_two::KeyGenFirstMsg::create();
    let party_one_second_message = party_one::KeyGenSecondMsg::verify_and_decommit(
        comm_witness,
        &party_two_first_message.d_log_proof,
    )
    .expect("failed to verify and decommit");

    let _party_two_second_message = party_two::KeyGenSecondMsg::verify_commitments_and_dlog_proof(
        &party_one_first_message,
        &party_one_second_message,
    )
    .expect("failed to verify commitments and DLog proof");
    // init HSMCL keypair:
    let seed: BigInt = BigInt::from_str_radix(
        "314159265358979323846264338327950288419716939937510582097494459230781640628620899862803482534211706798214808651328230664709384460955058223172535940812848",
        10,
    ).unwrap();
    let (hsmcl,hsmcl_setup)=party_one::HSMCL::generate_keypair(&seed);
    let party1_private=party_one::Party1Private::set_private_key(&_ec_key_pair_party1, &hsmcl);
    let _party_two_hsmcl_setup=
    party_two::Party2Setup::verify_setup(&hsmcl_setup, &seed).expect("failed to pass setup verify");

}

#[cfg(test)]
fn test_two_party_sign() {
    ////////// Simulate KeyGen /////////////////
    // assume party1 and party2 engaged with KeyGen in the past resulting in
    // party1 owning private share and HSMCL key-pair
    // party2 owning private share and HSMCL setup(cl group and PK)
    let (_party_one_private_share_gen, comm_witness, ec_key_pair_party1) =
        party_one::KeyGenFirstMsg::create_commitments();
    let (party_two_private_share_gen, ec_key_pair_party2) = party_two::KeyGenFirstMsg::create();

    //pi (nothing up my sleeve)
    let seed: BigInt = BigInt::from_str_radix(
        "314159265358979323846264338327950288419716939937510582097494459230781640628620899862803482534211706798214808651328230664709384460955058223172535940812848",
        10,
    ).unwrap();
    let (hsmcl,hsmcl_setup)=party_one::HSMCL::generate_keypair(&seed);
    let party1_private=party_one::Party1Private::set_private_key(&ec_key_pair_party1, &hsmcl);
    let party2_hsmcl_setup=
    party_two::Party2Setup::verify_setup(&hsmcl_setup, &seed).expect("failed to pass setup verify");

    ////////// Start Signing /////////////////
    // creating the ephemeral private shares:

    let (eph_party_two_first_message, eph_comm_witness, eph_ec_key_pair_party2) =
        party_two::EphKeyGenFirstMsg::create_commitments();
    let (eph_party_one_first_message, eph_ec_key_pair_party1) =
        party_one::EphKeyGenFirstMsg::create();
    let eph_party_two_second_message = party_two::EphKeyGenSecondMsg::verify_and_decommit(
        eph_comm_witness,
        &eph_party_one_first_message,
    )
    .expect("party1 DLog proof failed");
    let _eph_party_one_second_message =
        party_one::EphKeyGenSecondMsg::verify_commitments_and_dlog_proof(
            &eph_party_two_first_message,
            &eph_party_two_second_message,
        )
        .expect("failed to verify commitments and DLog proof");
    
    let _party_one_hsmcl_public = 
    party_one::HSMCLPublic::generate_encrypted_share_and_proof(&hsmcl_setup, &eph_ec_key_pair_party1);
    let party2_private = party_two::Party2Private::set_private_key(&ec_key_pair_party2);
    let party2_public=
    party_two::Party2Public::verify_zkdlcl_proof(&party2_hsmcl_setup, &_party_one_hsmcl_public)
    .expect("failed to verify ZK-CLDL");
    let message = "Hello world";
    
    let pubkey =
        party_one::compute_pubkey(&party1_private, &party_two_private_share_gen.public_share);
    
    let partial_sig = party_two::PartialSig::compute(
        party2_public,
        &party2_private,
        &eph_ec_key_pair_party2,
        &eph_party_one_first_message.public_share,
        &pubkey,
        &message,
    );
    

    let signature = party_one::Signature::compute(
        &hsmcl_setup,
        &party1_private,
        partial_sig.c3,
        &eph_ec_key_pair_party1,
        &eph_party_two_second_message.comm_witness.public_share,
        &pubkey,
        &message,
    );

    party_one::verify(&signature, &pubkey, &message).expect("Invalid signature")
}