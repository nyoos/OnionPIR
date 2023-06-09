#include "server.h"
#include "utils.h"
#include <cstdlib>
#include <stdexcept>
#include <cassert>
#include <memory>
#include <bitset>


PirServer::PirServer(const PirParams &pir_params):
  pir_params_(pir_params),
  context_(pir_params.get_seal_params()),
  DBSize_(pir_params.get_DBSize()),
  evaluator_(context_),
  dims_(pir_params.get_dims()) {}

// Fills the database with random data
void PirServer::gen_data() {
  std::vector<Entry> data;
  data.reserve(pir_params_.get_num_entries());
  for (size_t i = 0; i < pir_params_.get_num_entries(); ++i){
    data.push_back(Entry(pir_params_.get_entry_size()));
    for (size_t j = 0; j < pir_params_.get_entry_size(); ++j) {
      data[i][j] = (rand() % 255);
    }
  }
  set_database(data);
}


std::vector<seal::Ciphertext> PirServer::evaluate_first_dim(std::vector<seal::Ciphertext> & selection_vector) {
  int size_of_other_dims = DBSize_ / dims_[0];
  std::vector<seal::Ciphertext> result;
  // for (int j = 0; j < size_of_other_dims; j++){ 
  //   seal::Ciphertext cipher_result;
  //   result.push_back(cipher_result);
  // }

  for (int i = 0; i < size_of_other_dims; i++) {
    seal::Ciphertext cipher_result;
    evaluator_.multiply_plain(selection_vector[0], db_[i], cipher_result);
    result.push_back(cipher_result);
  }

  for (int i = 1; i < selection_vector.size(); i++) {
    for (int j = 0; j < size_of_other_dims; j++){ 
      seal::Ciphertext cipher_result;
      evaluator_.multiply_plain(selection_vector[i], db_[i * size_of_other_dims + j], cipher_result);
      evaluator_.add_inplace(result[j],cipher_result);
    }
  }

  for (auto & ciphertext : result){
    evaluator_.transform_from_ntt_inplace(ciphertext);
  }
  return result;
}

// Computes a dot product between the selection vector and the database for the first dimension with a delayed modulus optimization. Selection vector should be transformed to ntt.
std::vector<seal::Ciphertext> PirServer::evaluate_first_dim_delayed_mod(std::vector<seal::Ciphertext> & selection_vector) {
  int size_of_other_dims = DBSize_ / dims_[0];
  std::vector<seal::Ciphertext> result;

  auto &coeff_modulus = pir_params_.get_seal_params().coeff_modulus();
  size_t coeff_count = pir_params_.get_seal_params().poly_modulus_degree();
  size_t coeff_mod_count = coeff_modulus.size();
  size_t encrypted_ntt_size = selection_vector[0].size();

  seal::Ciphertext ct_acc;
  for (int col_id = 0; col_id < size_of_other_dims; ++col_id){
    std::vector<std::vector<uint128_t>> buffer(encrypted_ntt_size, std::vector<uint128_t>(coeff_count * coeff_mod_count, 1));
    for (int i = 0; i < dims_[0]; i++){
      for(size_t poly_id = 0; poly_id < encrypted_ntt_size; poly_id++){
        utils::multiply_poly_acum(selection_vector[i].data(poly_id), db_[col_id + i * size_of_other_dims].data(), coeff_count * coeff_mod_count, buffer[poly_id].data());
      }
    }
    ct_acc = selection_vector[0];
    for (size_t poly_id = 0; poly_id < encrypted_ntt_size; poly_id++) {
      auto ct_ptr = ct_acc.data(poly_id);
      auto pt_ptr = buffer[poly_id];
      for (int mod_id = 0; mod_id < coeff_mod_count; mod_id++) {
        auto mod_idx = (mod_id * coeff_count);
        
        for (int coeff_id = 0; coeff_id < coeff_count; coeff_id++) {
          pt_ptr[coeff_id + mod_idx] = pt_ptr[coeff_id + mod_idx] % static_cast<__uint128_t>(coeff_modulus[mod_id].value());
          ct_ptr[coeff_id + mod_idx] = static_cast<uint64_t>(pt_ptr[coeff_id + mod_idx]);
        }
      }
    }
    evaluator_.transform_from_ntt_inplace(ct_acc);
    result.push_back(ct_acc);
  }

  return result;
}

// Expands the first query ciphertext into a selection vector of ntt-processed ciphertexts where the ith ciphertext encodes the ith bit of the first query ciphertext.
std::vector<seal::Ciphertext> PirServer::expand_first_query_dim(uint32_t client_id, seal::Ciphertext ciphertext) {
  seal::EncryptionParameters params = pir_params_.get_seal_params();
  std::vector<Ciphertext> expanded_query;
  int poly_degree = params.poly_modulus_degree();

  // Expand ciphertext into 2^expansion_factor individual ciphertexts (number of bits) = size of first dimension
  int expansion_factor = std::log2(dims_[0]);

  std::vector<Ciphertext> cipher_vec((size_t) pow(2,expansion_factor));
  cipher_vec[0] = ciphertext;

  for (size_t a = 0; a < expansion_factor; a++) {

    int expansion_const = pow(2, a);

    for (size_t b = 0; b < expansion_const; b++) {
      Ciphertext cipher0 = cipher_vec[b];
      evaluator_.apply_galois_inplace(cipher0,
                                      poly_degree/expansion_const + 1,
                                      client_keys_[client_id]);
      Ciphertext cipher1;
      shift_polynomial(params, cipher0, cipher1, -expansion_const);
      shift_polynomial(params, cipher_vec[b], cipher_vec[b + expansion_const], -expansion_const);
      evaluator_.add_inplace(cipher_vec[b], cipher0);
      evaluator_.sub_inplace(cipher_vec[b + expansion_const], cipher1);
    }
  }

  for (auto & ciphertext : cipher_vec) {
    evaluator_.transform_to_ntt_inplace(ciphertext);
  }
  return cipher_vec;
}

void PirServer::set_client_keys(uint32_t client_id, seal::GaloisKeys client_key) {
  client_keys_[client_id] = client_key;
}


  void PirServer::set_client_decryptor(uint32_t client_id, seal::Decryptor* client_decryptor) {
    client_decryptors_[client_id] = client_decryptor;
  }

std::vector<seal::Ciphertext> PirServer::make_query(uint32_t client_id, PirQuery query) {
  std::vector<seal::Ciphertext> first_dim_selection_vector = expand_first_query_dim(client_id, query[0]);

  // for (auto & ct : first_dim_selection_vector) {
  //   Plaintext pt;
  //   client_decryptors_[client_id]->decrypt(ct, pt);
  //   std::cout << pt.to_string() << ", " ;
  // }
  std::vector<seal::Ciphertext> result =  evaluate_first_dim_delayed_mod(first_dim_selection_vector);
  // std::vector<seal::Ciphertext> result =  evaluate_first_dim(first_dim_selection_vector);


  return result;
}

// Sets database by turning data into a stream of bits then encoding the bits into the plaintext. Any left over space in the DB is padded by 1s.
void PirServer::set_database(std::vector<Entry> new_db) {
  db_ = Database();

  // Flattens data into vector of u8s and pads each entry with 0s to entry_size number of bytes.
  size_t total_size = 0;
  for (Entry & entry : new_db){
    if (entry.size() <= pir_params_.get_entry_size()) {
      entry.resize(pir_params_.get_entry_size(), 0);
    } else {
      throw std::invalid_argument("Entry size is too large");
    }
  }
  std::vector<uint8_t> data;
  data.reserve(total_size);
  for (const Entry & entry : new_db) {
    data.insert(data.end(), entry.begin(), entry.end());
  }

  set_database_from_bytes(data);
}


// Encodes the stream of bytes into plaintext coefficients by simply packing as many bytes into each coefficient as possible. However each plaintext always ends aligned to the end of an entry (no entries are split across multiple plaintexts).
void PirServer::set_database_from_bytes(const std::vector<uint8_t> & data) {
  // Get necessary parameters
  size_t bytes_per_coeff = pir_params_.get_num_bytes_per_coeff();
  size_t num_bytes_per_plaintext = pir_params_.get_num_bytes_per_plaintext();

  db_ = Database();

  auto data_iterator = data.begin();
  while (data_iterator != data.end()) {
    seal::Plaintext plaintext(pir_params_.get_seal_params().poly_modulus_degree());
    for (int i = 0; i < num_bytes_per_plaintext && data_iterator != data.end(); i += bytes_per_coeff){ 
      std::string bit_str;
      for (int j = 0 ; j < bytes_per_coeff && data_iterator != data.end(); ++j){
        bit_str = std::bitset<8>(*(data_iterator++)).to_string() + bit_str;
      }
      plaintext[i / bytes_per_coeff] = std::bitset<64>(bit_str).to_ullong();
    }
    db_.push_back(plaintext);
  }

  // Pad database until DBSize_
  for (size_t i = db_.size(); i < DBSize_; i++){
    db_.push_back(seal::Plaintext(pir_params_.get_seal_params().poly_modulus_degree()));
    // Pad each plaintext with a 1
    db_[i][0] = 1;
  }

  // Process database
  preprocess_ntt();
}

void PirServer::preprocess_ntt(){
  for (auto & plaintext : db_){
    evaluator_.transform_to_ntt_inplace(plaintext, context_.first_parms_id());
  }
}