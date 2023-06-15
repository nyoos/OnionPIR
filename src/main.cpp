#include "pir.h"
#include "server.h"
#include <iostream>
#include <chrono>

int main() {
  PirParams pir_params(2048, 2, 1000, 3);
  const int client_id = 0;
  pir_params.print_values();
  PirServer server(pir_params);
  // server.gen_data();

  #ifdef _DEBUG
  std::cout<< "===== Debug build =====" <<std::endl;
  #endif
  #ifdef _BENCHMARK
  std::cout<< " ===== Benchmark build =====" <<std::endl;
  #endif

  std::vector<Entry> data(1000);
  for (auto & entry : data) {
    entry.push_back(255);
    entry.push_back(173);
    entry.push_back(183);
  }
  server.set_database(data);
  std::cout << "DB set" << std::endl;

  PirClient client(pir_params);
  std::cout << "Client initialized" << std::endl;
  server.set_client_keys(client_id, client.create_galois_keys());
  server.set_client_decryptor(client_id, client.get_decryptor());
  std::cout << "Client registered" << std::endl;
  auto result = server.make_query(client_id ,client.generate_query(5));

  std::cout << "Result: " << std::endl;
  auto decrypted_result = client.decrypt_result(result);
  #ifdef _DEBUG
    for (auto & res : decrypted_result) {
      std::cout << res.to_string() << std::endl;
    }
  #endif
  print_entry(client.get_entry_from_plaintext(5, decrypted_result[0]));

  #ifdef _BENCHMARK
    std::cout << "Noise budget remaining: " << client.get_decryptor()->invariant_noise_budget(result[0]) << " bits" << std::endl;

    auto query = client.generate_query(5);
    auto start_time = std::chrono::high_resolution_clock::now();
    server.make_query_regular_mod(client_id, query);
    auto end_time = std::chrono::high_resolution_clock::now();
    auto elapsed_time = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time);
    std::cout<< "No delayed mod: " << elapsed_time.count() << " ms" <<std::endl;

    start_time = std::chrono::high_resolution_clock::now();
    server.make_query_delayed_mod(client_id, query);
    end_time = std::chrono::high_resolution_clock::now();
    elapsed_time = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time);
    std::cout<< "Delayed mod: " << elapsed_time.count() << " ms" <<std::endl;

    std::cout << std::endl;
  #endif
  return 0;
}


// Check timing and noise values 
// Move on to GSW
// ORAM Paper for GSW details