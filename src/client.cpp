#include "client.h"

PirClient::PirClient(const PirParams &pir_params):
  params_(pir_params.gen_params()),
  pir_params_(pir_params),
  context_(params_),
  evaluator_(context_),
  keygen_(context_),
  secret_key_(keygen_.secret_key()),
  encryptor_(context_, secret_key_),
  decryptor_(context_,secret_key_){}

PirQuery PirClient::generate_query(std::uint64_t index) {
  uint64_t poly_degree = params_.poly_modulus_degree();
  
  // The number of bits is equal to the size of the first dimension
  uint64_t bits_per_ciphertext = pir_params_.dims[0];

  uint64_t size_of_other_dims = pir_params_.DBSize / pir_params_.dims[0];

  std::vector<seal::Plaintext> plain_query;
  plain_query.push_back(seal::Plaintext(poly_degree));

  uint64_t inverse = 0;
  seal::util::try_invert_uint_mod(bits_per_ciphertext, params_.plain_modulus(), inverse);
 
  plain_query[0][index / size_of_other_dims] = inverse;
  
  PirQuery query;
  for (int i = 0; i < plain_query.size(); i++) {
    seal::Ciphertext x_encrypted;
    encryptor_.encrypt(plain_query[i], x_encrypted);
    query.push_back(x_encrypted);
  }
  return query;
}

seal::GaloisKeys PirClient::create_galois_keys() {
  
}