#pragma once
#include <ostream>
#include <sstream>
#include <string>
#include <utility>

namespace lookup_output {
// JSON strings are escaped first; the complete JSON then becomes one CSV field.
inline void json_string(std::ostream& out, const std::string& value) {
  static constexpr char hex[] = "0123456789abcdef";
  out << '"';
  for (unsigned char c : value) {
    if (c == '"' || c == '\\') out << '\\' << static_cast<char>(c);
    else if (c < 32) out << "\\u00" << hex[c >> 4] << hex[c & 15];
    else out << static_cast<char>(c);
  }
  out << '"';
}
template <typename Get>
void candidates_csv(std::ostream& out, std::size_t count, Get get) {
  std::ostringstream json;
  json << '[';
  for (std::size_t i = 0; i < count; ++i) {
    if (i) json << ',';
    const auto candidate = get(i);
    json << '[';
    json_string(json, candidate.first);
    json << ',' << candidate.second << ']';
  }
  json << ']';
  out << '"';
  for (char c : json.str()) {
    if (c == '"') out << '"';
    out << c;
  }
  out << '"';
}
}  // namespace lookup_output
