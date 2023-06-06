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
    for (int i = 0; i < params_.poly_modulus_degree() && i < entry.size(); i++) {
      plain[i] = entry[i] % params_.plain_modulus().value();
    }
    evaluator_.transform_to_ntt_inplace(plain, context_.first_parms_id());
    db_.push_back(plain);
  }
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
  return result;
}


std::vector<seal::Ciphertext> PirServer::expand_first_query_dim(uint32_t client_id, seal::Ciphertext ciphertext) {
  std::vector<Ciphertext> expanded_query;
  int poly_degree = params_.poly_modulus_degree();

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
      shift_polynomial(params_, cipher0, cipher1, -expansion_const);
      shift_polynomial(params_, cipher_vec[b], cipher_vec[b + expansion_const], -expansion_const);
      evaluator_.add_inplace(cipher_vec[b], cipher0);
      evaluator_.sub_inplace(cipher_vec[b + expansion_const], cipher1);
    }
  }
  return cipher_vec;
}

void PirServer::set_client_keys(uint32_t client_id, seal::GaloisKeys client_key) {
  client_keys_[client_id] = client_key;
}

void PirServer::register_client(PirClient* client) {
  set_client_keys(next_client_id, client->create_galois_keys());
  client_decryptors_[next_client_id] = client->get_decryptor();
  client->client_id = next_client_id++;
}


std::vector<seal::Ciphertext> PirServer::make_query(uint32_t client_id, PirQuery query) {
  std::vector<seal::Ciphertext> first_dim_selection_vector = expand_first_query_dim(client_id, query[0]);

  // for (auto & ct : first_dim_selection_vector) {
  //   Plaintext pt;
  //   client_decryptors_[client_id]->decrypt(ct, pt);
  //   std::cout << pt.to_string() << ", " ;
  // }
  std::cout << std::endl;
  std::vector<seal::Ciphertext> result =  evaluate_first_dim(first_dim_selection_vector);


  return result;
}