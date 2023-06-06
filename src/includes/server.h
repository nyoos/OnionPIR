#pragma once

#include "seal/seal.h"
#include "pir.h"
#include "client.h"

typedef std::vector<seal::Plaintext> Database;
typedef std::vector<uint64_t> Entry;

class PirServer {
  public:
    PirServer(const PirParams &pir_params);
    /* Replaces the database with random data */
    void gen_data();
    void set_database(std::vector<Entry> new_db);
    Database get_database();
    std::vector<seal::Ciphertext> make_query(uint32_t client_id, PirQuery query);
    void register_client(PirClient* client);

  private:
    seal::EncryptionParameters params_;
    uint64_t DBSize_;
    seal::SEALContext context_;
    seal::Evaluator evaluator_;
    std::vector<uint64_t> dims_;
    std::map<uint32_t, seal::GaloisKeys> client_keys_;
    std::map<uint32_t, seal::Decryptor*> client_decryptors_;
    Database db_;
    uint32_t next_client_id = 0;


    std::vector<seal::Ciphertext> expand_first_query_dim(uint32_t client_id, seal::Ciphertext ciphertext);
    std::vector<seal::Ciphertext> evaluate_first_dim(std::vector<seal::Ciphertext> & selection_vector);
    void set_client_keys(uint32_t client_id, seal::GaloisKeys client_key);
};