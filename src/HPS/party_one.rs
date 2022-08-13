use class_group::primitives::cl_dl_public_setup::{
    decrypt, verifiably_encrypt, CLDLProof, CLGroup, Ciphertext as CLCiphertext, PK, SK,
};

use curv::arithmetic::*;
use curv::cryptographic_primitives::commitments::hash_commitment::HashCommitment;
use curv::cryptographic_primitives::commitments::traits::Commitment;
use curv::cryptographic_primitives::hashing::{Digest, DigestExt};
use curv::cryptographic_primitives::proofs::sigma_dlog::*;
use curv::cryptographic_primitives::proofs::sigma_ec_ddh::*;
use curv::cryptographic_primitives::proofs::ProofError;
use curv::elliptic::curves::{secp256_k1::Secp256k1, Point, Scalar};
use curv::BigInt;
use sha2::Sha256;
use subtle::ConstantTimeEq;

use super::party_two::EphKeyGenFirstMsg as Party2EphKeyGenFirstMessage;
use super::party_two::EphKeyGenSecondMsg as Party2EphKeyGenSecondMessage;
use super::SECURITY_BITS;
use crate::Error::{self, InvalidSig};


//****************** Begin: Party One structs ******************//
#[derive(Clone, Debug)]
pub struct EcKeyPair {
    pub public_share: Point<Secp256k1>,
    secret_share: Scalar<Secp256k1>,
}

#[derive(Clone, Debug)]
pub struct CommWitness {
    pub pk_commitment_blind_factor: BigInt,
    pub zk_pok_blind_factor: BigInt,
    pub public_share: Point<Secp256k1>,
    pub d_log_proof: DLogProof<Secp256k1, Sha256>,
}

#[derive(Clone, Debug)]
pub struct KeyGenFirstMsg {
    pub pk_commitment: BigInt,
    pub zk_pok_commitment: BigInt,
}

#[derive(Debug)]
pub struct KeyGenSecondMsg {
    pub comm_witness: CommWitness,
}

#[derive(Debug)]
pub struct HSMCL {
    pub public: PK,
    pub secret: SK,
    pub cl_group: CLGroup,
}

#[derive(Debug)]
pub struct  HSMCLSetup{
    pub public: PK,
    pub cl_group: CLGroup,
}

#[derive(Debug)]
pub struct HSMCLPublic {
    pub proof: CLDLProof,
    pub encrypted_share: CLCiphertext,
    pub public_share: Point<Secp256k1>,
}

#[derive(Debug)]
pub struct SignatureRecid {
    pub d: BigInt,
    pub z: BigInt,
    pub recid: u8,
}

#[derive(Debug)]
pub struct Signature {
    pub d: BigInt,
    pub z: BigInt,
}

#[derive(Clone)]
pub struct Party1Private {
    s1: Scalar<Secp256k1>,
    hsmcl_pub: PK,
    hsmcl_priv: SK,
}

#[derive(Clone, Debug)]
pub struct EphEcKeyPair {
    pub public_share: Point<Secp256k1>,
    secret_share: Scalar<Secp256k1>,
}

#[derive(Debug)]
pub struct EphKeyGenFirstMsg {
    pub d_log_proof: ECDDHProof<Secp256k1, Sha256>,
    pub public_share: Point<Secp256k1>,
    pub c: Point<Secp256k1>, //c = secret_share * base_point2
}

#[derive(Debug)]
pub struct EphKeyGenSecondMsg {}

//****************** End: Party One structs ******************//

impl KeyGenFirstMsg {
    pub fn create_commitments() -> (KeyGenFirstMsg, CommWitness, EcKeyPair) {
        let base = Point::generator();

        let secret_share = Scalar::<Secp256k1>::random();
        //in Lindell's protocol range proof works only for x1<q/3
        //let secret_share: Scalar<Secp256k1> =
        //    Scalar::<Secp256k1>::from(&secret_share.to_bigint().div_floor(&BigInt::from(3)));

        let public_share = base * &secret_share;

        let d_log_proof = DLogProof::prove(&secret_share);
        // we use hash based commitment
        let pk_commitment_blind_factor = BigInt::sample(SECURITY_BITS);
        let pk_commitment =
            HashCommitment::<Sha256>::create_commitment_with_user_defined_randomness(
                &BigInt::from_bytes(public_share.to_bytes(true).as_ref()),
                &pk_commitment_blind_factor,
            );

        let zk_pok_blind_factor = BigInt::sample(SECURITY_BITS);
        let zk_pok_commitment =
            HashCommitment::<Sha256>::create_commitment_with_user_defined_randomness(
                &BigInt::from_bytes(d_log_proof.pk_t_rand_commitment.to_bytes(true).as_ref()),
                &zk_pok_blind_factor,
            );
        let ec_key_pair = EcKeyPair {
            public_share,
            secret_share,
        };
        (
            KeyGenFirstMsg {
                pk_commitment,
                zk_pok_commitment,
            },
            CommWitness {
                pk_commitment_blind_factor,
                zk_pok_blind_factor,
                public_share: ec_key_pair.public_share.clone(),
                d_log_proof,
            },
            ec_key_pair,
        )
    }

    pub fn create_commitments_with_fixed_secret_share(
        secret_share: Scalar<Secp256k1>,
    ) -> (KeyGenFirstMsg, CommWitness, EcKeyPair) {
        let base = Point::generator();
        let public_share = base * &secret_share;

        let d_log_proof = DLogProof::prove(&secret_share);

        let pk_commitment_blind_factor = BigInt::sample(SECURITY_BITS);
        let pk_commitment =
            HashCommitment::<Sha256>::create_commitment_with_user_defined_randomness(
                &BigInt::from_bytes(public_share.to_bytes(true).as_ref()),
                &pk_commitment_blind_factor,
            );

        let zk_pok_blind_factor = BigInt::sample(SECURITY_BITS);
        let zk_pok_commitment =
            HashCommitment::<Sha256>::create_commitment_with_user_defined_randomness(
                &BigInt::from_bytes(d_log_proof.pk_t_rand_commitment.to_bytes(true).as_ref()),
                &zk_pok_blind_factor,
            );

        let ec_key_pair = EcKeyPair {
            public_share,
            secret_share,
        };
        (
            KeyGenFirstMsg {
                pk_commitment,
                zk_pok_commitment,
            },
            CommWitness {
                pk_commitment_blind_factor,
                zk_pok_blind_factor,
                public_share: ec_key_pair.public_share.clone(),
                d_log_proof,
            },
            ec_key_pair,
        )
    }
}

impl KeyGenSecondMsg {
    pub fn verify_and_decommit(
        comm_witness: CommWitness,
        proof: &DLogProof<Secp256k1, Sha256>,
    ) -> Result<KeyGenSecondMsg, ProofError> {
        DLogProof::verify(proof)?;
        Ok(KeyGenSecondMsg { comm_witness })
    }
}

pub fn compute_pubkey(
    party_one_private: &Party1Private,
    other_share_public_share: &Point<Secp256k1>,
) -> Point<Secp256k1> {
    other_share_public_share * &party_one_private.s1-Point::generator()
}

impl Party1Private {
    pub fn set_private_key(ec_key: &EcKeyPair, hsmcl: &HSMCL) -> Party1Private {
        Party1Private {
            s1: ec_key.secret_share.clone(),
            hsmcl_pub: hsmcl.public.clone(),
            hsmcl_priv: hsmcl.secret.clone(),
        }
    }
}

impl HSMCL {
    pub fn generate_keypair(seed: &BigInt)-> (HSMCL, HSMCLSetup){
        let cl_group=CLGroup::new_from_setup(&1348, seed);
        let (secret_key,public_key)=cl_group.keygen();
        (HSMCL { 
            public:public_key.clone(), 
            secret: secret_key, 
            cl_group: cl_group.clone(),
         },
        HSMCLSetup{
            public: public_key.clone(),
            cl_group: cl_group.clone(),
        },
    )
    }
}

impl HSMCLPublic{
    pub fn generate_encrypted_share_and_proof(
        hsmcl_setup:&HSMCLSetup,
        keygen: &EphEcKeyPair   
    )->HSMCLPublic{
        let (ciphertext, proof) = verifiably_encrypt(
            &hsmcl_setup.cl_group,
            &hsmcl_setup.public,
            (&keygen.secret_share, &keygen.public_share),
        );
        HSMCLPublic { 
            proof, 
            encrypted_share: ciphertext,
            public_share: keygen.public_share.clone(),
        }
    }
}

impl EphKeyGenFirstMsg {
    pub fn create() -> (EphKeyGenFirstMsg, EphEcKeyPair) {
        let base = Point::generator();
        let secret_share = Scalar::<Secp256k1>::random();
        let public_share = base * &secret_share;
        let h = Point::<Secp256k1>::base_point2();
        let w = ECDDHWitness {
            x: secret_share.clone(),
        };
        let c = h * &secret_share;
        let delta = ECDDHStatement {
            g1: base.to_point(),
            h1: public_share.clone(),
            g2: h.clone(),
            h2: c.clone(),
        };
        let d_log_proof = ECDDHProof::prove(&w, &delta);
        let ec_key_pair = EphEcKeyPair {
            public_share: public_share.clone(),
            secret_share,
        };
        (
            EphKeyGenFirstMsg {
                d_log_proof,
                public_share,
                c,
            },
            ec_key_pair,
        )
    }
}

impl EphKeyGenSecondMsg {
    pub fn verify_commitments_and_dlog_proof(
        party_two_first_message: &Party2EphKeyGenFirstMessage,
        party_two_second_message: &Party2EphKeyGenSecondMessage,
    ) -> Result<EphKeyGenSecondMsg, ProofError> {
        let party_two_pk_commitment = &party_two_first_message.pk_commitment;
        let party_two_zk_pok_commitment = &party_two_first_message.zk_pok_commitment;
        let party_two_zk_pok_blind_factor =
            &party_two_second_message.comm_witness.zk_pok_blind_factor;
        let party_two_public_share = &party_two_second_message.comm_witness.public_share;
        let party_two_pk_commitment_blind_factor = &party_two_second_message
            .comm_witness
            .pk_commitment_blind_factor;
        let party_two_d_log_proof = &party_two_second_message.comm_witness.d_log_proof;
        let mut flag = true;
        if party_two_pk_commitment
            != &HashCommitment::<Sha256>::create_commitment_with_user_defined_randomness(
                &BigInt::from_bytes(party_two_public_share.to_bytes(true).as_ref()),
                party_two_pk_commitment_blind_factor,
            )
        {
            flag = false
        }
        if party_two_zk_pok_commitment
            != &HashCommitment::<Sha256>::create_commitment_with_user_defined_randomness(
                &Sha256::new()
                    .chain_points([&party_two_d_log_proof.a1, &party_two_d_log_proof.a2])
                    .result_bigint(),
                party_two_zk_pok_blind_factor,
            )
        {
            flag = false
        }
        if !flag {
            return Err(ProofError);
        }
        let delta = ECDDHStatement {
            g1: Point::generator().to_point(),
            h1: party_two_public_share.clone(),
            g2: Point::<Secp256k1>::base_point2().clone(),
            h2: party_two_second_message.comm_witness.c.clone(),
        };
        party_two_d_log_proof.verify(&delta)?;
        Ok(EphKeyGenSecondMsg {})
    }
}

impl Signature {
    pub fn compute(
        hsmcl: &HSMCLSetup,
        party_one_private: &Party1Private,
        partial_sig_c3: CLCiphertext,
        ephemeral_local_share: &EphEcKeyPair,
        ephemeral_other_public_share: &Point<Secp256k1>,
        pubkey:&Point<Secp256k1>,
        message: &str,
    ) -> Signature {
        //compute r = k2* R1
        let r = ephemeral_other_public_share * &ephemeral_local_share.secret_share;

        let rx = r
            .x_coord()
            .unwrap()
            .mod_floor(Scalar::<Secp256k1>::group_order());
        
        let e=Sha256::new()
            .chain_point(&pubkey)
            .chain_bigint(&BigInt::from_bytes(&message.as_bytes()))
            .result_bigint()
            .mod_floor(Scalar::<Secp256k1>::group_order());
        
        let d= rx+e;
        let s1=&party_one_private.s1.to_bigint();
        let s1_inv = BigInt::mod_inv(s1, Scalar::<Secp256k1>::group_order()).unwrap();

        let z_tag = decrypt(
            &hsmcl.cl_group,
            &party_one_private.hsmcl_priv,
            &partial_sig_c3,
        );
        let z_tag_tag = BigInt::mod_mul(
            &s1_inv,
            &z_tag.to_bigint(),
            Scalar::<Secp256k1>::group_order(),
        );
        let z=BigInt::mod_sub(
            &z_tag_tag, 
            &d, 
            Scalar::<Secp256k1>::group_order()
        );
        
        Signature { d, z }
    }
}

pub fn verify(
    signature: &Signature,
    pubkey: &Point<Secp256k1>,
    message: &str,
) -> Result<(), Error> {
    let z_fe = Scalar::<Secp256k1>::from(&signature.z);
    let dz = BigInt::mod_add(
        &signature.z,
        &signature.d, 
        Scalar::<Secp256k1>::group_order()
    );
    
    let dz_fe = Scalar::<Secp256k1>::from(&dz);
    let u1 = Point::generator() * z_fe;
    let u2 = pubkey * dz_fe;
    let r=u1+u2;
    let rx=&r.x_coord().
                    unwrap().
                    mod_floor(Scalar::<Secp256k1>::group_order());
    let e=Sha256::new()
            .chain_point(&pubkey)
            .chain_bigint(&BigInt::from_bytes(&message.as_bytes()))
            .result_bigint()
            .mod_floor(Scalar::<Secp256k1>::group_order());
    let rx_plus_e_byte = &BigInt::to_bytes(&(rx+e));
    let d_byte = &BigInt::to_bytes(&signature.d);
    
    if d_byte.ct_eq(rx_plus_e_byte).unwrap_u8() == 1
    {
        Ok(())
    }
    else {
        Err(InvalidSig)
    }
}