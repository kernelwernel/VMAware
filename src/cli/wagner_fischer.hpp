#include "globals.hpp"
#include "types.hpp"


#include <string>
#include <string_view>
#include <vector>
#include <algorithm>
#include <iostream>

using sv = std::string_view;

// https://en.wikipedia.org/wiki/Wagner%E2%80%93Fischer_algorithm
// this function is used for argument corrections in CLI tools. 
// The performance might be questionable, but it's nothing critical.
// It's only used for finding unrecognised arguments anyway, it's
// a debug utility for crashes.  
u8 wagner_fischer(
    sv a,
    sv b
) {
    u8 a_length = static_cast<u8>(a.length());
    u8 b_length = static_cast<u8>(b.length());

    if (a_length > b_length) {
        std::swap(a, b);
        std::swap(a_length, b_length);
    }

    std::vector<u8> curr_row(a_length + 1);
    std::vector<u8> prev_row(a_length + 1);

    curr_row.reserve(std::max(a_length, b_length));
    prev_row.reserve(std::max(a_length, b_length));

    for (u8 j = 0; j <= a_length; ++j) {
        prev_row[j] = j;
    }

    for (u8 i = 1; i <= b_length; ++i) {
        curr_row[0] = i;

        for (u8 j = 1; j <= a_length; ++j) {
            u8 add = prev_row[j] + 1;
            u8 del = curr_row[j - 1] + 1;
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


template <std::size_t N>
std::vector<std::string> suggest(
    const sv misspelled_word, 
    const std::array<std::pair<const char*, arg_enum>, N> &dictionary
) {
    std::vector<std::pair<u8, std::string>> candidates;
    candidates.reserve(N);

    for (const auto& word : dictionary) {
        const u8 distance = wagner_fischer(word.first, misspelled_word);
        if (distance <= 2) {
            candidates.emplace_back(distance, word.first);
        }
    }

    std::sort(
        candidates.begin(), 
        candidates.end(),
        [](const auto& a, const auto& b) {
            return a.first < b.first;
        }
    );

    std::vector<std::string> suggestions = {};
    suggestions.reserve(candidates.size());

    for (const auto& [distance, word] : candidates) {
        suggestions.push_back(word);
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
        std::cerr << bold + suggestions.at(i);
        std::cerr << ansi_exit;
    }

    std::cerr << "\"?\n";
}