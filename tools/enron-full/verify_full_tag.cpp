#define main prefuzzdup_original_main
#include "main.cpp"
#undef main

#include <algorithm>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace {

std::string without_eol(std::string value) {
    while (!value.empty() && (value.back() == '\r' || value.back() == '\n')) value.pop_back();
    return value;
}

std::vector<std::string> parse_csv_line(const std::string& line) {
    std::vector<std::string> fields;
    std::string field;
    bool quoted = false;
    for (std::size_t index = 0; index < line.size(); ++index) {
        const char character = line[index];
        if (quoted) {
            if (character == '"') {
                if (index + 1 < line.size() && line[index + 1] == '"') {
                    field.push_back('"');
                    ++index;
                } else {
                    quoted = false;
                }
            } else {
                field.push_back(character);
            }
        } else if (character == ',') {
            fields.push_back(field);
            field.clear();
        } else if (character == '"' && field.empty()) {
            quoted = true;
        } else if (character == '"') {
            fail("quotation mark is only allowed at the start of a quoted CSV field");
        } else {
            field.push_back(character);
        }
    }
    if (quoted) fail("unterminated quoted CSV field");
    fields.push_back(field);
    return fields;
}

std::ifstream open_csv(const fs::path& path) {
    std::ifstream stream(path);
    if (!stream) fail("cannot open " + path.string());
    return stream;
}

std::vector<std::vector<std::string>> read_all_csv(const fs::path& path) {
    std::ifstream stream = open_csv(path);
    std::vector<std::vector<std::string>> rows;
    std::string line;
    while (std::getline(stream, line)) {
        if (!line.empty()) rows.push_back(parse_csv_line(without_eol(line)));
    }
    if (!stream.eof()) fail("failed while reading " + path.string());
    return rows;
}

void expect_header(const std::vector<std::string>& actual, const std::vector<std::string>& expected) {
    if (actual != expected) fail("CSV header mismatch");
}

int hex_value(char character) {
    if (character >= '0' && character <= '9') return character - '0';
    if (character >= 'a' && character <= 'f') return character - 'a' + 10;
    fail("invalid lowercase hexadecimal character: " + std::string(1, character));
}

Bytes parse_hex(const std::string& value) {
    if (value.size() % 2) fail("hexadecimal value has odd length");
    Bytes result;
    result.reserve(value.size() / 2);
    for (std::size_t index = 0; index + 1 < value.size(); index += 2) {
        result.push_back(static_cast<std::uint8_t>(
            (hex_value(value[index]) << 4) | hex_value(value[index + 1])
        ));
    }
    return result;
}

bool is_lower_hex(const std::string& value, std::size_t expected_size) {
    return value.size() == expected_size && std::all_of(value.begin(), value.end(), [](char character) {
        return (character >= '0' && character <= '9') || (character >= 'a' && character <= 'f');
    });
}

Bytes extract_body(const Bytes& raw, const std::string& source) {
    Bytes normalized;
    normalized.reserve(raw.size());
    for (std::size_t index = 0; index < raw.size(); ++index) {
        if (raw[index] == '\r' && index + 1 < raw.size() && raw[index + 1] == '\n') continue;
        normalized.push_back(raw[index]);
    }
    const std::array<Bytes::value_type, 2> separator = {'\n', '\n'};
    const auto position = std::search(
        normalized.begin(), normalized.end(), separator.begin(), separator.end()
    );
    if (position == normalized.end()) fail("no header/body separator: " + source);
    Bytes body(position + 2, normalized.end());
    std::size_t begin = 0;
    std::size_t end = body.size();
    const auto whitespace = [](std::uint8_t value) {
        return value == ' ' || value == '\t' || value == '\n' || value == '\r' ||
               value == '\v' || value == '\f';
    };
    while (begin < end && whitespace(body[begin])) ++begin;
    while (end > begin && whitespace(body[end - 1])) --end;
    body.erase(body.begin() + static_cast<Bytes::difference_type>(end), body.end());
    body.erase(body.begin(), body.begin() + static_cast<Bytes::difference_type>(begin));
    return body;
}

std::uint64_t parse_unsigned(const std::string& value, const std::string& field) {
    try {
        if (value.empty() || value.find('-') != std::string::npos) throw std::invalid_argument(value);
        return std::stoull(value);
    } catch (const std::exception&) {
        fail("invalid unsigned integer in " + field + ": " + value);
    }
}

}  // namespace

int main(int argc, char** argv) {
    try {
        if (argc != 2 && argc != 3) {
            std::cerr << "usage: verify_full_tag <full50wTest.staging-dir> [maildir]\n";
            return 2;
        }
        const fs::path staging = argv[1];
        const fs::path maildir = argc == 3 ? fs::path(argv[2]) : staging.parent_path() / "maildir";
        if (!fs::is_directory(maildir)) fail("maildir directory not found next to staging directory");

        std::size_t edge_checked = 0;
        std::size_t edge_matched = 0;
        {
            const auto rows = read_all_csv(staging / "edge_cases.csv");
            if (rows.empty()) fail("edge_cases.csv is empty");
            expect_header(rows.front(), {"name", "input_hex", "expected_hex"});
            for (std::size_t index = 1; index < rows.size(); ++index) {
                const auto& row = rows[index];
                if (row.size() != 3) fail("edge_cases.csv row must have 3 fields");
                const std::string actual = hex(make_tag(parse_hex(row[1]), "text"));
                ++edge_checked;
                if (actual == row[2]) ++edge_matched;
                else std::cerr << "edge mismatch " << row[0] << ": cpp=" << actual
                               << " expected=" << row[2] << "\n";
            }
        }

        std::ifstream tags_stream = open_csv(staging / "tags.csv");
        std::ifstream manifest_stream = open_csv(staging / "manifest.csv");
        std::string tag_header;
        std::string manifest_header;
        if (!std::getline(tags_stream, tag_header)) fail("cannot read tags.csv header");
        if (!std::getline(manifest_stream, manifest_header)) fail("cannot read manifest.csv header");
        expect_header(parse_csv_line(without_eol(tag_header)), {"id", "type", "tag_hex"});
        expect_header(
            parse_csv_line(without_eol(manifest_header)),
            {"id", "mailbox", "source_path", "body_sha256", "body_size_bytes", "normalized_word_count"}
        );

        std::unordered_map<std::string, std::string> tags_by_body_hash;
        std::unordered_set<std::string> seen_ids;
        std::unordered_set<std::string> seen_sources;
        std::size_t bodies_checked = 0;
        std::size_t bodies_matched = 0;
        std::size_t distinct_tag_computations = 0;
        std::size_t mismatches = 0;
        std::vector<std::string> mismatch_samples;
        std::string tag_line;
        std::string manifest_line;
        while (std::getline(tags_stream, tag_line) && std::getline(manifest_stream, manifest_line)) {
            if (tag_line.empty() || manifest_line.empty()) fail("unexpected empty CSV data row");
            const auto tag_row = parse_csv_line(without_eol(tag_line));
            const auto manifest_row = parse_csv_line(without_eol(manifest_line));
            if (tag_row.size() != 3) fail("tags.csv row must have 3 fields");
            if (manifest_row.size() != 6) fail("manifest.csv row must have 6 fields");
            const std::string& id = tag_row[0];
            if (id != manifest_row[0]) fail("tags.csv and manifest.csv IDs are not aligned: " + id);
            if (!seen_ids.insert(id).second) fail("duplicate tags.csv ID: " + id);
            if (!seen_sources.insert(manifest_row[2]).second) fail("duplicate source path: " + manifest_row[2]);
            if (tag_row[1] != "text") fail("non-text tag type for " + id);
            if (!is_lower_hex(tag_row[2], 64) || !is_lower_hex(manifest_row[3], 64)) {
                fail("invalid hexadecimal field for " + id);
            }
            const std::uint64_t declared_size = parse_unsigned(manifest_row[4], "body_size_bytes");
            (void)parse_unsigned(manifest_row[5], "normalized_word_count");

            fs::path source = maildir / fs::path(manifest_row[2]);
            if (!fs::exists(source)) {
                const std::string filename = source.filename().string();
                if (!filename.empty() && filename.back() == '_') {
                    fs::path alternate = source;
                    alternate.replace_filename(filename.substr(0, filename.size() - 1) + ".");
                    if (fs::exists(alternate)) source = alternate;
                }
            }
            const Bytes raw = read_file(source);
            const Bytes body = extract_body(raw, manifest_row[2]);
            if (body.size() != declared_size) fail("body size mismatch for " + id);
            const std::string body_hash = hex(sha256(body));
            if (body_hash != manifest_row[3]) fail("body SHA-256 mismatch for " + id);

            auto cached = tags_by_body_hash.find(body_hash);
            std::string actual;
            if (cached == tags_by_body_hash.end()) {
                actual = hex(make_tag(body, "text"));
                tags_by_body_hash.emplace(body_hash, actual);
                ++distinct_tag_computations;
            } else {
                actual = cached->second;
            }
            ++bodies_checked;
            if (actual == tag_row[2]) ++bodies_matched;
            else {
                ++mismatches;
                if (mismatch_samples.size() < 20) {
                    mismatch_samples.push_back(id + " cpp=" + actual + " python=" + tag_row[2]);
                }
            }
            if (bodies_checked % 50'000 == 0) {
                std::cerr << "  verified " << bodies_checked << "/517401\r" << std::flush;
            }
        }
        std::cerr << "\n";
        if (tags_stream.bad() || manifest_stream.bad()) fail("failed while reading public CSV files");
        const bool tags_remaining = static_cast<bool>(std::getline(tags_stream, tag_line));
        const bool manifest_remaining = static_cast<bool>(std::getline(manifest_stream, manifest_line));
        if (tags_remaining || manifest_remaining || bodies_checked != 517'401) {
            fail("tags.csv and manifest.csv do not contain exactly 517401 aligned rows");
        }

        std::ofstream report(staging / "cpp_verification.json");
        if (!report) fail("cannot write cpp_verification.json");
        report << "{\n"
               << "  \"verifier\": \"tools/enron-full/verify_full_tag.cpp\",\n"
               << "  \"verifies_by_including\": \"PreFuzzDup/src/main.cpp make_tag/simhash_text\",\n"
               << "  \"tag_rows\": " << bodies_checked << ",\n"
               << "  \"manifest_rows\": " << bodies_checked << ",\n"
               << "  \"edge_cases_checked\": " << edge_checked << ",\n"
               << "  \"edge_cases_matched\": " << edge_matched << ",\n"
               << "  \"bodies_checked\": " << bodies_checked << ",\n"
               << "  \"bodies_matched\": " << bodies_matched << ",\n"
               << "  \"distinct_tag_computations\": " << distinct_tag_computations << ",\n"
               << "  \"mismatch_count\": " << mismatches << ",\n"
               << "  \"mismatches\": [";
        for (std::size_t index = 0; index < mismatch_samples.size(); ++index) {
            report << (index ? ", " : "") << "\"" << mismatch_samples[index] << "\"";
        }
        report << "]\n}\n";
        if (!report) fail("failed while writing cpp_verification.json");

        std::cout << "edge_cases " << edge_matched << "/" << edge_checked
                  << ", bodies " << bodies_matched << "/" << bodies_checked
                  << ", distinct_tags " << distinct_tag_computations
                  << ", mismatches " << mismatches << "\n";
        return mismatches == 0 && edge_matched == edge_checked && bodies_matched == bodies_checked ? 0 : 1;
    } catch (const std::exception& error) {
        std::cerr << "ERROR: " << error.what() << "\n";
        return 1;
    }
}
