use hps::party_one::Signature;
use curv::elliptic::curves::Secp256k1;
use curv::{arithmetic::Converter, elliptic::curves::Point};
use curv::BigInt;

mod hps;
use crate::hps::{party_one, party_two};

#[derive(Copy,PartialEq,Clone,Debug)]
pub enum Error {
    InvalidKey,
    InvalidSS,
    InvaildCom,
    InvalidSig,
}
struct PartyOneSignInput{
    setup:party_one::HSMCLSetup,
    pub_key: Point<Secp256k1>,
    private:party_one::Party1Private,
}



struct PartyTwoSignInput{
    setup:party_two::Party2Setup,
    pub_key:Point<Secp256k1>,
    private:party_two::Party2Private,
}

fn two_party_key_generation(seed:BigInt)->(PartyOneSignInput,PartyTwoSignInput){
    let (party_one_first_message, comm_witness, ec_key_pair_party1) =
        party_one::KeyGenFirstMsg::create_commitments();
    println!("P1 sends first message: commit DL");

    let (party_two_first_message, ec_key_pair_party2) = party_two::KeyGenFirstMsg::create();
    println!("P2 sends first message: proof DL");

    let party_one_second_message = party_one::KeyGenSecondMsg::verify_and_decommit(
        comm_witness,
        &party_two_first_message.d_log_proof,
    )
    .expect("failed to verify and decommit");
    print!("P1 sends second message: decommit DL");

    let _party_two_second_message = party_two::KeyGenSecondMsg::verify_commitments_and_dlog_proof(
        &party_one_first_message,
        &party_one_second_message,
    )
    .expect("failed to verify commitments and DLog proof");
    println!("P2 verifies commit and zero knowledge");

    let (hsmcl,party1_hsmcl_setup)=party_one::HSMCL::generate_keypair(&seed);
    let party1_private=party_one::Party1Private::set_private_key(&ec_key_pair_party1, &hsmcl);
    let party2_hsmcl_setup=
    party_two::Party2Setup::verify_setup(&party1_hsmcl_setup, &seed).expect("failed to pass setup verify");
    let party2_private = party_two::Party2Private::set_private_key(&ec_key_pair_party2);
    println!("P1,P2 finish key generation of HPS-based hommomorphic encryption");
    (
        PartyOneSignInput{
            setup:party1_hsmcl_setup,
            pub_key:party_one::compute_pubkey(&party1_private, &ec_key_pair_party2.public_share),
            private:party1_private,
        },
        PartyTwoSignInput{
            setup:party2_hsmcl_setup,
            pub_key:party_two::compute_pubkey(&party2_private, &ec_key_pair_party1.public_share),
            private: party2_private,
        }
    )
}

fn two_party_signature(
    p1_input:&PartyOneSignInput,
    p2_input:&PartyTwoSignInput,
    message:&str
)->Signature{
    let (eph_party_two_first_message, eph_comm_witness, eph_ec_key_pair_party2) =
        party_two::EphKeyGenFirstMsg::create_commitments();
    println!("P2 sends first message: commit DL");

    let (eph_party_one_first_message, eph_ec_key_pair_party1) =
        party_one::EphKeyGenFirstMsg::create();
    println!("P1 sends first message: proof DL");

    let eph_party_two_second_message = party_two::EphKeyGenSecondMsg::verify_and_decommit(
        eph_comm_witness,
        &eph_party_one_first_message,
    )
    .expect("party1 DLog proof failed");
    println!("P2 sends second message: decommit DL");

    let _eph_party_one_second_message =
        party_one::EphKeyGenSecondMsg::verify_commitments_and_dlog_proof(
            &eph_party_two_first_message,
            &eph_party_two_second_message,
        )
        .expect("failed to verify commitments and DLog proof");
    println!("P1 verifies commit and zero knowledge");

    let party_one_hsmcl_public = 
    party_one::HSMCLPublic::generate_encrypted_share_and_proof(&p1_input.setup, &eph_ec_key_pair_party1);
    let party2_public=
    party_two::Party2Public::verify_zkdlcl_proof(&p2_input.setup, &party_one_hsmcl_public)
    .expect("failed to verify ZK-CLDL");
    
    let partial_sig = party_two::PartialSig::compute(
        party2_public,
        &p2_input.private,
        &eph_ec_key_pair_party2,
        &eph_party_one_first_message.public_share,
        &p2_input.pub_key,
        &message,
    );
    println!("P2 computes c3 according to c1");
    
    let signature = party_one::Signature::compute(
        &p1_input.setup,
        &p1_input.private,
        partial_sig.c3,
        &eph_ec_key_pair_party1,
        &eph_party_two_second_message.comm_witness.public_share,
        &p1_input.pub_key,
        &message,
    );
    println!("P1 computes final signature");
    party_one::verify(&signature, &p1_input.pub_key, &message).expect("Invalid signature");
    signature
}


fn main() {
    let seed: BigInt = BigInt::from_str_radix(
        "314159265358979323846264338327950288419716939937510582097494459230781640628620899862803482534211706798214808651328230664709384460955058223172535940812848",
        10,
    ).unwrap();
    println!("key generation starts!");
    let (p1_input,p2_input)=two_party_key_generation(seed);
    println!("key generation ends!");
    let message = "Hello world";
    println!("signature startS!");
    let signture = two_party_signature(&p1_input, &p2_input, &message);
    println!("signature ends!");
    println!("Final signature of {} is {:#?}",&message, &signture);
    
}
