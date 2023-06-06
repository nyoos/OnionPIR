#include "pir.h"
#include "server.h"
#include <iostream>

int main() {
  // PirParams pir_params(1024, 3, 256);
  // PirServer server(pir_params);
  // server.gen_data();
  // auto plain = server.get_database()[0];
  // for (int i = 0; i < pir_params.n; i++){
  //   std::cout<< plain[i] << ", ";
  // }
  // std::cout << std::endl;
  // return 0;
  PirParams pir_params(1024, 3, 257);
  PirServer server(pir_params);
  std::vector<Entry> new_db;
  for (int i = 0; i < 256; i++) {
    for (int j = 0; j < 4; j++) {
      Entry en;
      en.push_back(i+j);
      en.push_back(1);
      new_db.push_back(en);
    }
  }
  server.set_database(new_db);
  std::cout << "DB set" << std::endl;
  PirClient client(pir_params);
  std::cout << "Client initialized" << std::endl;
  server.register_client(&client);
  std::cout << "Client registered" << std::endl;
  auto result = server.make_query(client.client_id,client.generate_query(2));

  std::cout << "Result: " << std::endl;
  auto decrypted_result = client.decrypt_result(result);
  for (auto & res : decrypted_result) {
    std::cout << res.to_string() << ", " ;
  }
  std::cout << std::endl;
  result = server.make_query(client.client_id,client.generate_query(3));

  std::cout << "Result: " << std::endl;
  decrypted_result = client.decrypt_result(result);
  for (auto & res : decrypted_result) {
    std::cout << res.to_string() << ", " ;
  }
  std::cout << std::endl;
  result = server.make_query(client.client_id,client.generate_query(4));

  std::cout << "Result: " << std::endl;
  decrypted_result = client.decrypt_result(result);
  for (auto & res : decrypted_result) {
    std::cout << res.to_string() << ", " ;
  }
  std::cout << std::endl;
  return 0;
}