#include <string>

std::string build_token(const std::string& header, const std::string& payload) {
    return header + "." + payload + ".sig";
}
