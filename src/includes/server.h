#pragma once

#include "seal/seal.h"
#include "pir.h"
#include "client.h"

typedef std::vector<seal::Plaintext> Database;

class PirServer {
  public:
    PirServer(const PirParams &pir_params);
    /*!
      Replaces the database with random data 
    */
    void gen_data();
    /*!
      Sets the database to a new database
    */
    void set_database(std::vector<Entry> new_db);
    std::vector<seal::Ciphertext> make_query(uint32_t client_id, PirQuery query);
    std::vector<seal::Ciphertext> make_query_delayed_mod(uint32_t client_id, PirQuery query);
    std::vector<seal::Ciphertext> make_query_regular_mod(uint32_t client_id, PirQuery query);
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

    /*!
      Expands the first query ciphertext into a selection vector of ciphertexts where the ith ciphertext encodes the ith bit of the first query ciphertext.
    */
    std::vector<seal::Ciphertext> expand_first_query_dim(uint32_t client_id, seal::Ciphertext ciphertext);
    /*!
      Performs a cross product between the first selection vector and the database.
    */
    std::vector<seal::Ciphertext> evaluate_first_dim(std::vector<seal::Ciphertext> & selection_vector);
    std::vector<seal::Ciphertext> evaluate_first_dim_delayed_mod(std::vector<seal::Ciphertext> & selection_vector);

    /*!
      Encodes data into plaintexts by encoding the stream of bits into plaintext coefficients. However each plaintext always ends aligned to the end of an entry (no entries are split across multiple plaintexts).
      @param data - Flattened vector of entry data
    */
    void set_database_from_bytes(const std::vector<uint8_t> & data);

    /*!
      Transforms the plaintexts in the database into their NTT representation. This speeds up computation but takes up more memory.
    */
    void preprocess_ntt();

};