#include "pir.h"
#include "server.h"
#include <iostream>

int main() {
  PirParams pir_params(1024, 3, 3000, 3);
  const int client_id = 0;
  pir_params.print_values();
  std::cout << pir_params.get_num_bytes_per_coeff() << std::endl;
  PirServer server(pir_params);
  // server.gen_data();
  std::vector<Entry> data(3000);
  for (auto & entry : data) {
    entry.push_back(255);
    entry.push_back(173);
    entry.push_back(64);
  }
  server.set_database(data);
  std::cout << "DB set" << std::endl;

  PirClient client(pir_params);
  std::cout << "Client initialized" << std::endl;
  server.set_client_keys(client_id, client.create_galois_keys());
  server.set_client_decryptor(client_id, client.get_decryptor());
  std::cout << "Client registered" << std::endl;
  auto result = server.make_query(client_id ,client.generate_query(2));

  std::cout << "Result: " << std::endl;
  auto decrypted_result = client.decrypt_result(result);
  for (auto & res : decrypted_result) {
    std::cout << res.to_string() << std::endl;
  }
  print_entry(client.get_entry_from_plaintext(2, decrypted_result[0]));
  std::cout << std::endl;
  return 0;
}