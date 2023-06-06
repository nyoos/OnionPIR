#include "client.h"

PirClient::PirClient(const PirParams &pir_params):
  params_(pir_params.gen_params()),
  DBSize_(pir_params.DBSize),
  dims_(pir_params.dims)
   {
    context_ = new seal::SEALContext(params_);
    evaluator_ = new seal::Evaluator(*context_);
    keygen_ = new seal::KeyGenerator(*context_);
    secret_key_ = &keygen_->secret_key();
    keygen_->create_public_key(public_key_);
    encryptor_ = new seal::Encryptor(*context_, public_key_);
    decryptor_ = new seal::Decryptor(*context_, *secret_key_);
  }

PirClient::~PirClient(){
  delete context_;
  delete evaluator_;
  delete keygen_;
  delete encryptor_;
  delete decryptor_;
}

seal::Decryptor* PirClient::get_decryptor() {
  return decryptor_;
}

PirQuery PirClient::generate_query(std::uint64_t index) {
  uint64_t poly_degree = params_.poly_modulus_degree();
  
  // The number of bits is equal to the size of the first dimension
  uint64_t bits_per_ciphertext = dims_[0];

  uint64_t size_of_other_dims = DBSize_ / dims_[0];

  std::vector<seal::Plaintext> plain_query;
  plain_query.push_back(seal::Plaintext(poly_degree));

  uint64_t inverse = 0;
  seal::util::try_invert_uint_mod(bits_per_ciphertext, params_.plain_modulus(), inverse);
 
  plain_query[0][index / size_of_other_dims] = inverse;
  
  PirQuery query;
  for (int i = 0; i < plain_query.size(); i++) {
    seal::Ciphertext x_encrypted;
    encryptor_->encrypt(plain_query[i], x_encrypted);
    query.push_back(x_encrypted);
  }
  return query;
}

seal::GaloisKeys PirClient::create_galois_keys() {
  std::vector<uint32_t> galois_elts = {1};

  // Compression factor determines how many bits there are per message (and hence the total query size), with bits per message = 2^compression_factor. 
  // For example, with compression factor = 11 and bit length = 4096, we end up with 2048 bits per message and a total query size of 2. 
  // The 2048 bits will be encoded in the first 2048 coeffs of the polynomial.
  // 2^compression_factor must be less than or equal to polynomial modulus degree and bit_length.
  int compression_factor = std::log2(dims_[0]);

  size_t min_ele = params_.poly_modulus_degree()/pow(2,compression_factor) + 1;
  for (size_t i = min_ele; i <= params_.poly_modulus_degree() + 1 ; i = (i-1)*2 + 1) {
      galois_elts.push_back(i);
  }
  seal::GaloisKeys galois_keys;
  keygen_->create_galois_keys(galois_elts, galois_keys);
  return galois_keys;
}


  std::vector<seal::Plaintext> PirClient::decrypt_result(std::vector<seal::Ciphertext> reply) {
    std::vector<seal::Plaintext> result(reply.size(), seal::Plaintext(params_.poly_modulus_degree()));
    for(size_t i = 0; i < reply.size(); i++){
      decryptor_->decrypt(reply[i], result[i]);
    }

    return result;
  }