#include "pir.h"
#include "server.h"
#include <iostream>

int main() {
  PirParams pir_params(1024, 3, 256);
  PirServer server(pir_params);
  server.gen_data();
  auto plain = server.get_database()[0];
  for (int i = 0; i < pir_params.n; i++){
    std::cout<< plain[i] << ", ";
  }
  std::cout << std::endl;
  return 0;
}