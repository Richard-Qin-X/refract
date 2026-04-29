#include <cassert>
#include <iostream>
#include <refract/sha256.hh>
#include <refract/span_utils.hh>
#include <string>
#include <vector>

using namespace refract;

struct TestCase {
    std::string name;
    std::string input;
    std::string expected_hex;
};

namespace {

void run_test(const TestCase& tc) {
    std::cout << "[RUNNING] " << tc.name << "..." << "\n";
    
    const_bytes_span input_span = as_bytes_view(tc.input);
    Sha256::Digest digest = Sha256::hash(input_span);
    std::string actual_hex = to_hex(as_bytes(digest));

    if (actual_hex == tc.expected_hex) {
        std::cout << "[PASS] " << tc.name << "\n";
    } else {
        std::cerr << "[FAIL] " << tc.name << "\n";
        std::cerr << "  Expected: " << tc.expected_hex << "\n";
        std::cerr << "  Actual:   " << actual_hex << "\n";
        std::exit(1);
    }
}

void test_million_a() {
    std::cout << "[RUNNING] Million 'a' test (FIPS 180-4)..." << "\n";
    std::string expected = "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0";
    
    Sha256 ctx;
    std::vector<uint8_t> chunk(1000, 'a');
    const_bytes_span chunk_span(chunk.data(), chunk.size());
    for (int i = 0; i < 1000; ++i) {
        ctx.update(chunk_span);
    }
    
    Sha256::Digest digest = ctx.finalize();
    std::string actual = to_hex(as_bytes(digest));
    
    if (actual == expected) {
        std::cout << "[PASS] Million 'a' test" << "\n";
    } else {
        std::cerr << "[FAIL] Million 'a' test" << "\n";
        std::cerr << "  Expected: " << expected << "\n";
        std::cerr << "  Actual:   " << actual << "\n";
        std::exit(1);
    }
}

} // namespace

int main() {

    std::string nist_56;
    for (int i = 0; i < 14; ++i) {
        for (int j = 0; j < 4; ++j) {
            nist_56 += static_cast<char>('a' + i + j);
        }
    }

    std::vector<TestCase> tests = {
        {
            "Empty String",
            "",
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        },
        {
            "Short String 'abc'",
            "abc",
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        },
        {
            "56-byte String (FIPS 180-4)",
            nist_56,
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
        }
    };

    for (const auto& tc : tests) {
        run_test(tc);
    }

    test_million_a();

    std::cout << "\nAll SHA-256 KAT tests passed!" << "\n";
    return 0;
}
