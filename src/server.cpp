#include "server.h"
#include <cstdlib>
#include <stdexcept>


PirServer::PirServer(const PirParams &pir_params):
  params_(pir_params.gen_params()),
  context_(params_),
  DBSize_(pir_params.DBSize),
  evaluator_(context_),
  dims_(pir_params.dims) {}

void PirServer::gen_data() {
  Database new_db;
  for (int i = 0; i < DBSize_; i++) {
    seal::Plaintext plain(params_.poly_modulus_degree());
    for(int j = 0; j < params_.poly_modulus_degree(); j++) {
      plain[j] = rand() % 255;
    }
    evaluator_.transform_to_ntt_inplace(plain, context_.first_parms_id());
    new_db.push_back(plain);
  }
  db_ = new_db;
}

Database PirServer::get_database(){
  return db_;
}

void PirServer::set_database(std::vector<Entry> new_db){
  if (new_db.size() != DBSize_) {
    throw std::invalid_argument("Database size does not match");
  }
  db_ = Database();
  for (Entry & entry : new_db) {
    seal::Plaintext plain(params_.poly_modulus_degree());
    for (int i = 0; i < params_.poly_modulus_degree(); i++) {
      plain[i] = entry[i] % params_.plain_modulus().value();
    }
    evaluator_.transform_to_ntt_inplace(plain, context_.first_parms_id());
    db_.push_back(plain);
  }
}

std::vector<seal::Ciphertext> PirServer::evaluate_first_dim(std::vector<seal::Ciphertext> & selection_vector) {
  int size_of_other_dims = DBSize_ / dims_[0];
  std::vector<seal::Ciphertext> result;
  for (int j = 0; j < size_of_other_dims; j++){ 
    seal::Ciphertext cipher_result;
    result.push_back(cipher_result);
  }

  for (int i = 0; i < DBSize_; i += size_of_other_dims) {
    for (int j = 0; j < size_of_other_dims; j++){ 
      seal::Ciphertext cipher_result;
      evaluator_.multiply_plain(selection_vector[i], db_[i * size_of_other_dims + j], cipher_result);
      evaluator_.add_inplace(result[i],cipher_result);
    }
  }
  return result;
}

std::vector<seal::Ciphertext> PirServer::expand_first_query_dim(PirQuery query) {
  std::vector<Ciphertext> expanded_query;
  int poly_degree = params_.poly_modulus_degree();

  // Expand ciphertext into 2^expansion_factor number of bits = size of first dimension
  int expansion_factor = std::log2(dims_[0]);

  for (size_t j = 0; j < query.size(); j++) {
    std::vector<Ciphertext> cipher_vec((size_t) pow(2,expansion_factor));
    cipher_vec[0] = query[j];

    for (size_t a = 0; a < expansion_factor; a++) {

      int expansion_const = pow(2, a);

      for (size_t b = 0; b < expansion_const; b++) {
        Ciphertext cipher0 = cipher_vec[b];
        evaluator.apply_galois_inplace(cipher0,
                                       poly_degree/expansion_const + 1,
                                       client_context.galois_keys);
        Ciphertext cipher1;
        shift_polynomial(cipher0, cipher1, -expansion_const);
        shift_polynomial(cipher_vec[b], cipher_vec[b + expansion_const], -expansion_const);
        evaluator.add_inplace(cipher_vec[b], cipher0);
        evaluator.sub_inplace(cipher_vec[b + expansion_const], cipher1);
      }
      // Show the expansion
      Plaintext plain;
      for (int i = 0; i < 2*expansion_const; i++) {
          decryptor->decrypt(cipher_vec[i], plain);
          std::cout << plain.to_string() << "|| " ;
      }
      std::cout << std::endl;

    }

    expanded_query.reserve(expanded_query.size() + cipher_vec.size());
    expanded_query.insert(expanded_query.end(), std::make_move_iterator(cipher_vec.begin()), std::make_move_iterator(cipher_vec.end()));
  }

  return expanded_query;
}