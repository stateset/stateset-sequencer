use crate::crypto::signing::SigningError;
#[cfg(test)]
use ml_dsa::signature::Keypair;
use ml_dsa::signature::{Signer, Verifier};
use ml_dsa::{
    EncodedVerifyingKey as MlDsaEncodedVerifyingKey, KeyGen, MlDsa65, Signature as MlDsaSignature,
    VerifyingKey as MlDsaVerifyingKey,
};

#[cfg(test)]
pub(crate) fn ml_dsa_65_public_key_from_seed(seed: &[u8; 32]) -> Vec<u8> {
    let signing_key = <MlDsa65 as KeyGen>::from_seed(&(*seed).into());
    signing_key.verifying_key().encode().as_slice().to_vec()
}

pub(crate) fn sign_ml_dsa_65(seed: &[u8; 32], message: &[u8; 32]) -> Result<Vec<u8>, SigningError> {
    let signing_key = <MlDsa65 as KeyGen>::from_seed(&(*seed).into());
    let signature: MlDsaSignature<MlDsa65> = signing_key
        .try_sign(message)
        .map_err(|error| SigningError::SigningFailed(error.to_string()))?;
    Ok(signature.encode().as_slice().to_vec())
}

pub(crate) fn verify_ml_dsa_65(
    message: &[u8; 32],
    signature: &[u8],
    public_key: &[u8],
) -> Result<(), SigningError> {
    let encoded_vk = MlDsaEncodedVerifyingKey::<MlDsa65>::try_from(public_key)
        .map_err(|_| SigningError::InvalidPublicKeyFormat)?;
    let vk = MlDsaVerifyingKey::decode(&encoded_vk);

    let sig = MlDsaSignature::<MlDsa65>::try_from(signature)
        .map_err(|_| SigningError::InvalidSignatureFormat)?;

    vk.verify(message, &sig)
        .map_err(|_| SigningError::VerificationFailed)
}
