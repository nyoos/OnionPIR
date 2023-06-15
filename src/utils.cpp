#include "utils.h"

void utils::negacyclic_shift_poly_coeffmod(seal::util::ConstCoeffIter poly, size_t coeff_count, size_t shift, const seal::Modulus &modulus, seal::util::CoeffIter result){
  // Nothing to do
  if (shift == 0)
  {
      set_uint(poly, coeff_count, result);
      return;
  }

  uint64_t index_raw = shift;
  uint64_t coeff_count_mod_mask = static_cast<uint64_t>(coeff_count) - 1;
  for (size_t i = 0; i < coeff_count; i++, poly++, index_raw++)
  {
      uint64_t index = index_raw & coeff_count_mod_mask;
      if (!(index_raw & static_cast<uint64_t>(coeff_count)) || !*poly)
      {
          result[index] = *poly;
      }
      else
      {
          result[index] = modulus.value() - *poly;
      }
  }
}

void utils::shift_polynomial(seal::EncryptionParameters & params, seal::Ciphertext & encrypted, seal::Ciphertext & destination, size_t index){
  auto encrypted_count = encrypted.size();
  auto coeff_count = params.poly_modulus_degree();
  auto coeff_mod_count = params.coeff_modulus().size() - 1;
  destination = encrypted;
  for (int i = 0; i < encrypted_count; i++) {
    for (int j = 0; j < coeff_mod_count; j++) {
      negacyclic_shift_poly_coeffmod(encrypted.data(i) + (j * coeff_count),
                                     coeff_count, index,
                                     params.coeff_modulus()[j],
                                     destination.data(i) + (j * coeff_count));
    }
  }
}

