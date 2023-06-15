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



void PirParams::print_values() {
    std::cout << "===================================================" << std::endl;
    std::cout << "                   PIR PARAMETERS                    " << std::endl;
    std::cout << "===================================================" << std::endl;
    std::cout << "  num_entries_                  = " << num_entries_ << std::endl;
    std::cout << "  entry_size_                   = " << entry_size_ << std::endl;
    std::cout << "  DBSize_ (num plaintexts in database)                   = " << DBSize_ << std::endl;
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
    std::cout << "  seal_params_.plain_modulus().bitcount() = " << seal_params_.plain_modulus().bit_count() << std::endl;
    std::cout << "===================================================" << std::endl;
}

size_t PirParams::get_num_entries_per_plaintext() const{
  size_t total_bits = get_num_bits_per_plaintext();
  return total_bits / entry_size_;
}

size_t PirParams::get_entry_size() const {
  return entry_size_;
}

size_t PirParams::get_num_entries() const {
  return num_entries_;
}

size_t PirParams::get_num_bits_per_coeff() const{
  return seal_params_.plain_modulus().bit_count() - 1;
}

size_t PirParams::get_num_bits_per_plaintext() const{
  return get_num_bits_per_coeff() * seal_params_.poly_modulus_degree();
}


void print_entry(Entry entry){ 
  for (auto & val : entry) {
    std::cout << +val << ", ";
  }
  std::cout << std::endl;
}