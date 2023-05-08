#pragma once

#include "seal/seal.h"
#include "pir.h"

typedef std::vector<seal::Plaintext> Database;
typedef std::vector<uint64_t> Entry;

class PirServer {
  public:
    PirServer(const PirParams &pir_params);
    /* Replaces the database with random data */
    void gen_data();
    void set_database(std::vector<Entry> new_db);
    Database get_database();
    seal::Ciphertext make_query(PirQuery query);

  private:
    seal::EncryptionParameters params_;
    uint64_t DBSize_;
    seal::SEALContext context_;
    seal::Evaluator evaluator_;
    std::vector<uint64_t> dims_;
    Database db_;


    std::vector<seal::Ciphertext> expand_first_query_dim(PirQuery query);
    std::vector<seal::Ciphertext> evaluate_first_dim(std::vector<seal::Ciphertext> & selection_vector);
};