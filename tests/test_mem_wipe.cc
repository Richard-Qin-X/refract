#include "../src/internal/mem_wipe.hh"
#include <algorithm>
#include <array>
#include <cassert>
#include <cstdint>
#include <exception>
#include <iostream>
#include <span>
#include <vector>

using namespace refract;

int main() {
  try {
    std::cout << "[Test] Running test_mem_wipe...\n";

    // 1. Primitive object test
    {
      uint64_t secret = 0xDEADBEEFCAFEBABE;
      internal::mem_wipe(secret);
      assert(secret == 0);
    }

    // 2. Struct object test
    {
      struct Sensitive {
        std::array<char, 16> password;
        int pin;
      };
      Sensitive s = {.password = {'p', 'a', 's', 's'}, .pin = 1234};
      internal::mem_wipe(s);
      assert(s.pin == 0);
      for (const char c : s.password) {
        assert(c == 0);
      }
    }

    // 3. Array with count test
    {
      std::array<uint8_t, 1024> buffer{};
      std::ranges::fill(buffer, 0xAA);
      internal::mem_wipe(buffer.data(), buffer.size());
      for (const uint8_t b : buffer) {
        assert(b == 0);
      }
    }

    // 4. std::span interface test
    {
      std::vector<uint32_t> keys(10, 0x11223344);
      internal::mem_wipe(std::span<uint32_t>(keys));
      for (const uint32_t k : keys) {
        assert(k == 0);
      }
    }

    // 5. Edge cases
    {
      internal::mem_wipe<uint8_t>(nullptr, 100);
      uint8_t tiny = 42;
      internal::mem_wipe(&tiny, 0);
      assert(tiny == 42);
    }

    std::cout << "[Test] test_mem_wipe passed!\n";
  } catch (const std::exception &e) {
    std::cerr << "[Fatal] Unexpected exception in test_mem_wipe: " << e.what()
              << "\n";
    return 1;
  } catch (...) {
    std::cerr << "[Fatal] Unknown error in test_mem_wipe\n";
    return 1;
  }

  return 0;
}
