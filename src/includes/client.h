#pragma once

#include "pir.h"

class PirClient {
public:
    PirClient(const PirParams &pirparms);

    PirQuery generate_query(std::uint64_t index);

    seal::GaloisKeys create_galois_keys();

    // void decrypt_results(std::vector<seal::Ciphertext> reply);

    // seal::Plaintext decrypt_result(std::vector<seal::Ciphertext> reply);


private:
    seal::EncryptionParameters params_;
    PirParams pir_params_;

    seal::SecretKey get_decryptor();
    seal::Encryptor encryptor_;
    seal::Decryptor decryptor_;
    seal::Evaluator evaluator_;
    seal::KeyGenerator keygen_;
    seal::SEALContext context_;
    seal::SecretKey secret_key_;
};