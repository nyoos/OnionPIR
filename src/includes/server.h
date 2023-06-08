#pragma once

#include "seal/seal.h"
#include "pir.h"
#include "client.h"

typedef std::vector<seal::Plaintext> Database;

class PirServer {
  public:
    PirServer(const PirParams &pir_params);
    /* Replaces the database with random data */
    void gen_data();
    void set_database(std::vector<Entry> new_db);
    std::vector<seal::Ciphertext> make_query(uint32_t client_id, PirQuery query);
    void set_client_keys(uint32_t client_id, seal::GaloisKeys client_key);
    void set_client_decryptor(uint32_t client_id, seal::Decryptor* client_decryptor);

  private:
    uint64_t DBSize_;
    seal::SEALContext context_;
    seal::Evaluator evaluator_;
    std::vector<uint64_t> dims_;
    std::map<uint32_t, seal::GaloisKeys> client_keys_;
    std::map<uint32_t, seal::Decryptor*> client_decryptors_;
    Database db_;
    PirParams pir_params_;

    std::vector<seal::Ciphertext> expand_first_query_dim(uint32_t client_id, seal::Ciphertext ciphertext);
    std::vector<seal::Ciphertext> evaluate_first_dim(std::vector<seal::Ciphertext> & selection_vector);
    std::vector<uint64_t> entries_to_coeffs(std::vector<Entry> entries, size_t offset, size_t num_entries_to_convert);
    void set_database_from_bytes(const std::vector<uint8_t> & data);
    void preprocess_ntt();

};