#pragma once

#include "globals.hpp"
#include "types.hpp"

#include <string>
#include <vector>
#include <array>
#include <algorithm>

// https://en.wikipedia.org/wiki/Wagner%E2%80%93Fischer_algorithm
// this function is used for argument corrections in CLI tools.
// The performance might be questionable, but it's nothing critical.
// It's only used for finding unrecognised arguments anyway, it's
// a debug utility for crashes.
u8 wagner_fischer(const std::string& a_input, const std::string& b_input);
void manage_output(const std::vector<std::string>& suggestions);

template <std::size_t N>
std::vector<std::string> suggest(
    const std::string& misspelled_word,
    const std::array<std::pair<const char*, arg_enum>, N>& dictionary
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
        [](const std::pair<u8, std::string>& a, const std::pair<u8, std::string>& b) {
            return a.first < b.first;
        }
    );

    std::vector<std::string> suggestions;
    suggestions.reserve(candidates.size());

    for (const auto& candidate : candidates) {
        suggestions.push_back(candidate.second); // word
    }

    return suggestions;
}