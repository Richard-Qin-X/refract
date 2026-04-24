#include "refract/span_utils.hh"
#include <algorithm>
#include <array>
#include <cassert>
#include <cstdint>
#include <exception>
#include <iostream>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>

using namespace refract;

int main() {
  try {
    std::cout << "[Test] Running test_span_utils...\n";

    // 1. xor_buffers test
    {
      std::array<uint8_t, 4> a = {0x0F, 0xF0, 0xAA, 0x55};
      const std::array<uint8_t, 4> b = {0xF0, 0x0F, 0x55, 0xAA};
      xor_buffers(a, b);
      for (const uint8_t x : a) {
        assert(x == 0xFF);
      }

      try {
        std::array<uint8_t, 2> short_a = {0, 0};
        xor_buffers(short_a, b);
        assert(false);
      } catch (const std::invalid_argument &e) {
        // Expected size mismatch
        static_cast<void>(e);
      }
    }

    // 2. secure_compare test
    {
      const std::array<uint8_t, 4> d1 = {1, 2, 3, 4};
      const std::array<uint8_t, 4> d2 = {1, 2, 3, 4};
      const std::array<uint8_t, 4> d3 = {1, 2, 3, 5};
      assert(secure_compare(d1, d2) == true);
      assert(secure_compare(d1, d3) == false);
      assert(secure_compare(d1, std::span(d1).subspan(0, 3)) == false);
    }

    // 3. hex conversion tests
    {
      const std::array<uint8_t, 5> raw = {0x00, 0x42, 0xFF, 0xDE, 0xAD};
      const std::string hex = to_hex(raw);
      assert(hex == "0042ffdead");

      std::array<uint8_t, 5> back{};
      assert(from_hex(hex, back) == 5);
      assert(std::ranges::equal(raw, back));

      // Error cases
      try {
        from_hex("abc", back);
        assert(false);
      } catch (const std::invalid_argument &e) {
        static_cast<void>(e);
      }

      try {
        from_hex("zz", back);
        assert(false);
      } catch (const std::invalid_argument &e) {
        static_cast<void>(e);
      }

      std::array<uint8_t, 2> small{};
      try {
        from_hex("112233", small);
        assert(false);
      } catch (const std::out_of_range &e) {
        static_cast<void>(e);
      }
    }

    // 4. view helpers test
    {
      uint64_t val = 0x1122334455667788;
      const auto s = as_bytes(val);
      assert(s.size() == 8);

      const auto ws = as_writable_bytes(val);
      ws[0] = 0x00;
      assert(val != 0x1122334455667788);
    }

    // 5. safe_subspan test
    {
      const std::array<uint8_t, 6> buf = {0, 1, 2, 3, 4, 5};
      const auto s = std::span(buf);
      assert(safe_subspan(s, 2, 2).size() == 2);
      assert(safe_subspan(s, 2, 2)[0] == 2);

      try {
        safe_subspan(s, 10);
        assert(false);
      } catch (const std::out_of_range &e) {
        static_cast<void>(e);
      }
    }

    std::cout << "[Test] test_span_utils passed!\n";
  } catch (const std::exception &e) {
    std::cerr << "[Fatal] Unexpected exception in test_span_utils: " << e.what()
              << "\n";
    return 1;
  } catch (...) {
    std::cerr << "[Fatal] Unknown error in test_span_utils\n";
    return 1;
  }

  return 0;
}
