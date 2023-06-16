#include <cassert>
#include "external_prod.h"
#include "seal/util/polyarithsmallmod.h"
#include "utils.h"

void external_product(GSWCiphertext &gsw_enc, std::vector<std::vector<uint64_t>> &decomposed_bfv, std::shared_ptr<seal::SEALContext::ContextData> &context_data, int l, size_t ct_poly_size, seal::Ciphertext &res_ct) {
    // Get parameters
    auto &parms2 = context_data->parms();
    auto &coeff_modulus = parms2.coeff_modulus();
    size_t coeff_count = parms2.poly_modulus_degree();
    size_t coeff_mod_count = coeff_modulus.size();

    auto ntt_tables = context_data->small_ntt_tables();

    // Here we compute a cross product between the transpose of the decomposed BFV (a 2l vector of polynomials) and the GSW ciphertext (a 2lx2 matrix of polynomials) to obtain a size-2 vector of polynomials, which is exactly our result ciphertext.
    // We use an NTT multiplication to speed up polynomial multiplication, assuming that both the GSWCiphertext and decomposed bfv is in polynomial coefficient representation.

    for (auto & poly : gsw_enc) {
      seal::util::CoeffIter gsw_poly_ptr(poly);
      seal::util::ntt_negacyclic_harvey(gsw_poly_ptr, *ntt_tables);
    }
    for (auto & poly : decomposed_bfv) {
      seal::util::CoeffIter bfv_poly_ptr(poly);
      seal::util::ntt_negacyclic_harvey(bfv_poly_ptr, *ntt_tables);
    }

    // Use the delayed mod speedup
    std::vector<std::vector<uint128_t>> result(2, std::vector<uint128_t>(coeff_count * coeff_mod_count, 0));
    for (int k = 0; k < 2; ++k) {
        for (size_t j = 0; j < 2*l; j++) {
            seal::util::ConstCoeffIter encrypted_gsw_ptr(gsw_enc[k * 2 * l + j]);
            seal::util::ConstCoeffIter encrypted_rlwe_ptr(decomposed_bfv[j]);
            utils::multiply_poly_acum(encrypted_rlwe_ptr, encrypted_gsw_ptr, coeff_count * coeff_mod_count, result[k].data());
        }
    }
    
    for (size_t poly_id = 0; poly_id < 2; poly_id++) {
      auto ct_ptr = res_ct.data(poly_id);
      auto pt_ptr = result[poly_id];

      for (int mod_id = 0; mod_id < coeff_mod_count; mod_id++){
        auto mod_idx = (mod_id * coeff_count);
        
        for(int coeff_id = 0; coeff_id < coeff_count; coeff_id++){
          pt_ptr[coeff_id + mod_idx] = pt_ptr[coeff_id + mod_idx] % static_cast<__uint128_t>(coeff_modulus[mod_id].value());
          ct_ptr[coeff_id + mod_idx] = static_cast<uint64_t>(pt_ptr[coeff_id + mod_idx]);
        }
      }
    }
}

void decomp_rlwe128(seal::Ciphertext ct, const uint64_t l, std::shared_ptr<seal::SEALContext> context, std::vector<std::vector<uint64_t>> &output, int base_log2, seal::util::MemoryPool &pool) {
  // Reserve space in our output 
  assert(output.size() == 0);
  output.reserve(2*l);

  // Get parameters
  const uint64_t base = UINT64_C(1) << base_log2;
  const uint64_t mask = base -1 ;

  const auto & context_data = context->get_context_data(ct.parms_id());
  auto &parms = context_data->parms();
  auto &coeff_modulus = parms.coeff_modulus();
  size_t coeff_count = parms.poly_modulus_degree();
  size_t coeff_mod_count = coeff_modulus.size();
  size_t ct_poly_count = ct.size();
  assert(ct_poly_count == 2);
  int total_bits;

  // Start decomposing row wise. Note that the modulus of each row is base^(l-row)
  for (int j = 0; j < ct_poly_count; j++){
    total_bits = (context_data->total_coeff_modulus_bit_count());
    uint64_t *poly_ptr = ct.data(j);

    // This decomposes each coefficient by taking the modulus of the coefficient by the base for that given row.
    for (int p = 0; p < l; p++) {
      std::vector<uint64_t> row_coefficients(coeff_count * coeff_mod_count);
      const int shift_amount = ((total_bits) - ((p + 1) * base_log2));

      for (size_t k = 0; k < coeff_mod_count * coeff_count; k = k + 2) {
        auto ptr(allocate_uint(2, pool));
        ptr[0] = 0;
        ptr[1] = 1;
        seal::util::right_shift_uint128(&poly_ptr[k], shift_amount, ptr.get());
        uint64_t temp1 = ptr[0] & mask;
        row_coefficients[k] = temp1;
      }
      output.push_back(std::move(row_coefficients));
    }
  }
}