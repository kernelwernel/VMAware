#include "wagner_fischer.hpp"

#include <algorithm>
#include <iostream>

// https://en.wikipedia.org/wiki/Wagner%E2%80%93Fischer_algorithm
// this function is used for argument corrections in CLI tools.
// The performance might be questionable, but it's nothing critical.
// It's only used for finding unrecognised arguments anyway, it's
// a debug utility for crashes.
u8 wagner_fischer(const std::string& a_input, const std::string& b_input) {
    std::string a = a_input;
    std::string b = b_input;

    u8 a_length = static_cast<u8>(a.length());
    u8 b_length = static_cast<u8>(b.length());

    if (a_length > b_length) {
        std::swap(a, b);
        std::swap(a_length, b_length);
    }

    std::vector<u8> curr_row(a_length + 1);
    std::vector<u8> prev_row(a_length + 1);

    for (u8 j = 0; j <= a_length; ++j) {
        prev_row[j] = j;
    }

    for (u8 i = 1; i <= b_length; ++i) {
        curr_row[0] = i;

        for (u8 j = 1; j <= a_length; ++j) {
            const u8 add = prev_row[j] + 1;
            const u8 del = curr_row[j - 1] + 1;
            u8 change = prev_row[j - 1];

            if (a[j - 1] != b[i - 1]) {
                change += 1;
            }

            curr_row[j] = std::min({add, del, change});
        }

        std::swap(prev_row, curr_row);
    }

    return prev_row[a_length];
}

std::vector<std::string> suggest(const std::string& misspelled_word, const arg_table& dictionary) {
    std::vector<std::pair<u8, std::string>> candidates;
    candidates.reserve(dictionary.size());

    for (const auto& word : dictionary) {
        const u8 distance = wagner_fischer(word.first, misspelled_word);
        if (distance <= 2) {
            candidates.emplace_back(distance, word.first);
        }
    }

    std::sort(
        candidates.begin(),
        candidates.end(),
        [](const std::pair<u8, std::string>& a, const std::pair<u8, std::string>& b) {
            return a.first < b.first;
        }
    );

    std::vector<std::string> suggestions;
    suggestions.reserve(candidates.size());

    for (const auto& candidate : candidates) {
        suggestions.push_back(candidate.second);
    }

    return suggestions;
}

void manage_output(const std::vector<std::string>& suggestions) {
    if (suggestions.empty()) {
        return;
    }

    std::cerr << "Did you mean: \"";

    for (std::size_t i = 0; i < suggestions.size(); ++i) {
        if (i > 0) {
            std::cerr << ", ";
        }
        std::cerr << bold << suggestions.at(i) << ansi_exit;
    }

    std::cerr << "\"?\n";
}