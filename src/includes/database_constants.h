#pragma once

namespace DatabaseConstants {
    constexpr int PolyDegree = 4096;
    // constexpr int PlaintextModBits = 9;
    constexpr int PlaintextMod = 257;
    constexpr unsigned long long CiphertextMod1 = 21873307932344321;
    constexpr unsigned long long CiphertextMod2 = 14832153251168257; 
    // Ciphertext Mod1 + Mod2 has a total length of 109 bits
}