#include "pir.h"

#include <cassert>

seal::EncryptionParameters PirParams::get_seal_params() const{
  return seal_params_;
}

uint64_t PirParams::get_DBSize() const {
  return DBSize_;
}

std::vector<uint64_t> PirParams::get_dims() const {
  return dims_;
}

void negacyclic_shift_poly_coeffmod(ConstCoeffIter poly, size_t coeff_count, size_t shift, const Modulus &modulus, CoeffIter result){
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

void shift_polynomial(EncryptionParameters & params, Ciphertext & encrypted, Ciphertext & destination, size_t index){
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

void PirParams::print_values() {
    std::cout << "===================================================" << std::endl;
    std::cout << "                   PIR PARAMETERS                    " << std::endl;
    std::cout << "===================================================" << std::endl;
    std::cout << "  num_entries_                  = " << num_entries_ << std::endl;
    std::cout << "  entry_size_                   = " << entry_size_ << std::endl;
    std::cout << "  dimensions_                   = [ ";

    for (const auto& dim : dims_) {
        std::cout << dim << " ";
    }

    std::cout << "]" << std::endl;
    std::cout << "  seal_params_.poly_modulus_degree()  = " << seal_params_.poly_modulus_degree() << std::endl;

    auto coeff_modulus_size = seal_params_.coeff_modulus().size();
    std::cout << "  seal_params_.coeff_modulus().bit_count   = [";

    for (std::size_t i = 0; i < coeff_modulus_size - 1; i++) {
        std::cout << seal_params_.coeff_modulus()[i].bit_count() << " + ";
    }

    std::cout << seal_params_.coeff_modulus().back().bit_count();
    std::cout << "] bits" << std::endl;
    std::cout << "  seal_params_.coeff_modulus().size() = " << seal_params_.coeff_modulus().size() << std::endl;
    std::cout << "  seal_params_.plain_modulus().value() = " << seal_params_.plain_modulus().value() << std::endl;
    std::cout << "===================================================" << std::endl;
}

// Calculates the number of entries that each plaintext can contain, aligning the end of an entry to the end of a plaintext.
size_t PirParams::num_entries_per_plaintext() const{
  size_t bytes_per_coeff = (seal_params_.plain_modulus().bit_count() - 1) / 8;
  size_t num_coeffs_per_plaintext = seal_params_.poly_modulus_degree();
  size_t total_bytes = bytes_per_coeff * num_coeffs_per_plaintext;
  return total_bytes / entry_size_;
}

size_t PirParams::get_entry_size() const {
  return entry_size_;
}

size_t PirParams::get_num_entries() const {
  return num_entries_;
}

size_t PirParams::get_num_bytes_per_coeff() const{
  return (seal_params_.plain_modulus().bit_count() - 1) / 8;
}

// Calculates the number of bytes of data each plaintext contains, after aligning the end of an entry to the end of a plaintext.
size_t PirParams::get_num_bytes_per_plaintext() const{
  return num_entries_per_plaintext() * entry_size_;
}


void print_entry(Entry entry){ 
  for (auto & val : entry) {
    std::cout << +val << ", ";
  }
  std::cout << std::endl;
}