#pragma once
#include "seal/seal.h"
#include <vector>

// A GSWCiphertext is a flattened 2lx2 matrix of polynomials 
typedef std::vector<std::vector<uint128_t>> GSWCiphertext;

/*!
  Performs a gadget decomposition of a size 2 BFV ciphertext into 2 sets of rows of l polynomials (the 2 sets are concatenated into a single vector of vectors). Each polynomial coefficient encodes the value congruent to the original ciphertext coefficient modulus the value of base^(l-row).
  @param ct - input BFV ciphertext. Should be of size 2. 
  @param l - number of GSW rows
  @param context_data - SEAL context data
  @param output - output to store the decomposed ciphertext as a vector of vectors of polynomial coefficients
  @param base_log2 - value of log2(GSW base) (base must be a power of 2)
  @param pool - SEAL memory pool
*/
void decomp_rlwe128(seal::Ciphertext ct, const uint64_t l, std::shared_ptr<seal::SEALContext::ContextData> context_data, std::vector<std::vector<uint64_t>> &output, int base_log2, seal::util::MemoryPool &pool);

/*!
  Computes the external product between a GSW ciphertext and a decomposed BFV ciphertext.
  @param gsw_enc -GSW Ciphertext, should only encrypt 0 or 1 to prevent large noise growth
  @param rlwe_expansion - decomposed vector of BFV ciphertext
  @param context - SEAL context
  @param l - number of GSW rows
  @param ct_poly_size - number of ciphertext polynomials
  @param res_ct - output ciphertext
*/
void external_product(GSWCiphertext &gsw_enc, std::vector<uint64_t *> &decomposed_bfv, std::shared_ptr<seal::SEALContext> &context, int l, size_t ct_poly_size, seal::Ciphertext &res_ct);

/*!
  Generates a GSW gadget matrix with the specified parameters.
  @param context_data - SEAL context data
  @param l - number of GSW rows
  @param base_log2 - value of log2(GSW base) (base must be a power of 2)
*/
GSWCiphertext create_GSW_gadget(seal::SEALContext context, int base_log2, int l);