#pragma once

#include "pir.h"

class PirClient {
public:
    PirClient(const PirParams &pirparms);
    ~PirClient();

    PirQuery generate_query(std::uint64_t index);

    seal::GaloisKeys create_galois_keys();

    // void decrypt_results(std::vector<seal::Ciphertext> reply);

    std::vector<seal::Plaintext> decrypt_result(std::vector<seal::Ciphertext> reply);
    uint32_t client_id;
    seal::Decryptor* get_decryptor();


private:
    seal::EncryptionParameters params_;
    uint64_t DBSize_;
    std::vector<uint64_t> dims_;

    seal::Encryptor* encryptor_;
    seal::Decryptor* decryptor_;
    seal::Evaluator* evaluator_;
    seal::KeyGenerator* keygen_;
    seal::SEALContext* context_;
    seal::PublicKey public_key_;
    const seal::SecretKey* secret_key_;

};