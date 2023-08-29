#pragma once

#include "pir.h"
#include "server.h"

class PirClient {
public:
    PirClient(const PirParams &pirparms);
    ~PirClient();

    /*!
        Generates an OnionPIR query corresponding to the plaintext that encodes the given entry index.
    */
    PirQuery generate_query(std::uint64_t entry_index);

    seal::GaloisKeys create_galois_keys();

    std::vector<seal::Plaintext> decrypt_result(std::vector<seal::Ciphertext> reply);
    uint32_t client_id;
    seal::Decryptor* get_decryptor();
    /*!
        Retrieves an entry from the plaintext containing the entry.
    */
    Entry get_entry_from_plaintext(size_t entry_index, seal::Plaintext plaintext);

private:
    seal::EncryptionParameters params_;
    PirParams pir_params_;
    uint64_t DBSize_;
    std::vector<uint64_t> dims_;

    seal::Encryptor* encryptor_;
    seal::Decryptor* decryptor_;
    seal::Evaluator* evaluator_;
    seal::KeyGenerator* keygen_;
    seal::SEALContext* context_;
    seal::PublicKey public_key_;
    const seal::SecretKey* secret_key_;
    /*!
        Gets the corresponding plaintext index in a database for a given entry index
    */
    size_t get_database_plain_index(size_t entry_index);

    /*!
        Gets the query indexes for a given plaintext
    */
    std::vector<size_t> get_query_indexes(size_t plaintext_index);
};