#pragma once

#include "seal/seal.h"
#include <vector>
#include <stdexcept>

using namespace seal::util;
using namespace seal;

typedef std::vector<Ciphertext> PirQuery;

struct PirParams {
    uint64_t DBSize;                    // number of elements in the database
    uint64_t n;                         // Polynomial degree
    std::vector<seal::Modulus> cipher_coeff; // Ciphertext coefficients
    uint64_t plain_coeff;               // Plaintext coefficients
    std::vector<uint64_t> dims;                      // Number of dimensions

    PirParams(uint64_t DBSize, uint64_t ndim, uint64_t plain_coeff): 
        DBSize(DBSize),
        n(4096),
        cipher_coeff({14832153251168257, 21873307932344321}),   // Set to 109 bits
        plain_coeff(plain_coeff)
        {
            uint64_t first_dim = DBSize >> (ndim - 1);
            if (first_dim < 128) {
                throw std::invalid_argument("Size of first dimension is too small");
            }
            if ((first_dim & (first_dim - 1))) {
                throw std::invalid_argument("Size of database is not a power of 2");
            }
            dims.push_back(first_dim);
            for (uint i = 1; i < ndim; i++) {
                dims.push_back(2);
            }
        } 
    seal::EncryptionParameters gen_params() const;
};


void negacyclic_shift_poly_coeffmod(ConstCoeffIter poly, size_t coeff_count, size_t shift, const Modulus &modulus, CoeffIter result);
void shift_polynomial(EncryptionParameters & params, Ciphertext & encrypted, Ciphertext & destination, size_t index);