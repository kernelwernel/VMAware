#include "../src/vmaware.hpp"
#include <array>
#include <cstdlib>
#include <iostream>
#include <string>

static int pass_count = 0;
static int fail_count = 0;

static void check(bool condition, const char* label) {
    if (condition) {
        std::cout << "  PASS  " << label << "\n";
        ++pass_count;
    } else {
        std::cerr << "  FAIL  " << label << "\n";
        ++fail_count;
    }
}

static bool scoreboards_equal(
    const std::array<VM::core::brand_entry, VM::MAX_BRANDS>& a,
    const std::array<VM::core::brand_entry, VM::MAX_BRANDS>& b
) {
    for (std::size_t i = 0; i < VM::MAX_BRANDS; ++i) {
        if (a.at(i).name != b.at(i).name || a.at(i).score != b.at(i).score) {
            return false;
        }
    }
    return true;
}

static bool scoreboard_non_decreasing(
    const std::array<VM::core::brand_entry, VM::MAX_BRANDS>& a,
    const std::array<VM::core::brand_entry, VM::MAX_BRANDS>& b
) {
    for (std::size_t i = 0; i < VM::MAX_BRANDS; ++i) {
        if (b.at(i).score < a.at(i).score) {
            return false;
        }
    }
    return true;
}

int main() {
    // Phase 1: Mixed-flag behavior (MUST run first, cold caches)
    //
    // run_all() resets detected_count_num and brand_scoreboard to zero at the
    // start of every call, then re-accumulates from the technique cache for
    // only the enabled techniques. This means values are per-call scoped, not
    // globally accumulated. These tests verify that invariant.

    std::cout << "=== Mixed-flag: detected_count_num per-call scoping ===\n";
    {
        VM::detected_count(VM::HYPERVISOR_BIT);
        const auto num_single = VM::detected_count_num.load();

        VM::detected_count();
        const auto num_full = VM::detected_count_num.load();

        VM::detected_count(VM::HYPERVISOR_BIT);
        const auto num_single_again = VM::detected_count_num.load();

        check(num_full >= num_single,
              "detected_count_num for full run >= single-technique run");
        check(num_single_again == num_single,
              "detected_count_num recalculated per-call: restricted call matches first restricted call");
    }

    std::cout << "\n=== Mixed-flag: brand_scoreboard per-call scoping ===\n";
    {
        VM::brand(VM::HYPERVISOR_BIT);
        const auto scoreboard_after_single_brand = VM::core::brand_scoreboard;

        VM::detected_count();
        const auto scoreboard_after_full_detect = VM::core::brand_scoreboard;

        VM::brand(VM::HYPERVISOR_BIT);
        const auto scoreboard_after_single_brand_again = VM::core::brand_scoreboard;

        check(scoreboard_non_decreasing(scoreboard_after_single_brand, scoreboard_after_full_detect),
              "brand_scoreboard scores >= after full run vs single-technique run");
        check(scoreboards_equal(scoreboard_after_full_detect, scoreboard_after_single_brand_again),
              "brand_scoreboard unchanged when brand() returns from single_brand cache");
    }

    // Phase 2: Same-flag stability tests (caches fully warmed from Phase 1)
    //
    // run_all() re-accumulates all enabled techniques from cache on every call,
    // so repeated calls with the same flags must produce identical results.

    std::cout << "\n=== VM::detected_count() consistency ===\n";
    {
        const auto dc1 = VM::detected_count();
        const auto num1 = VM::detected_count_num.load();

        const auto dc2 = VM::detected_count();
        const auto num2 = VM::detected_count_num.load();

        const auto dc3 = VM::detected_count();
        const auto num3 = VM::detected_count_num.load();

        check(dc1 == dc2, "VM::detected_count() 2nd call matches 1st");
        check(dc1 == dc3, "VM::detected_count() 3rd call matches 1st");
        check(num1 == num2, "detected_count_num unchanged after 2nd VM::detected_count()");
        check(num1 == num3, "detected_count_num unchanged after 3rd VM::detected_count()");
    }

    std::cout << "\n=== VM::brand() consistency ===\n";
    {
        const std::string brand1 = VM::brand();
        const auto scoreboard1 = VM::core::brand_scoreboard;

        const std::string brand2 = VM::brand();
        const auto scoreboard2 = VM::core::brand_scoreboard;

        const std::string brand3 = VM::brand();
        const auto scoreboard3 = VM::core::brand_scoreboard;

        check(brand1 == brand2, "VM::brand() 2nd call matches 1st");
        check(brand1 == brand3, "VM::brand() 3rd call matches 1st");
        check(scoreboards_equal(scoreboard1, scoreboard2), "brand_scoreboard unchanged after 2nd VM::brand()");
        check(scoreboards_equal(scoreboard1, scoreboard3), "brand_scoreboard unchanged after 3rd VM::brand()");
    }

    std::cout << "\n=== VM::detect() consistency ===\n";
    {
        const bool result1 = VM::detect();
        const auto num1 = VM::detected_count_num.load();

        const bool result2 = VM::detect();
        const auto num2 = VM::detected_count_num.load();

        const bool result3 = VM::detect();
        const auto num3 = VM::detected_count_num.load();

        check(result1 == result2, "VM::detect() 2nd call matches 1st");
        check(result1 == result3, "VM::detect() 3rd call matches 1st");
        check(num1 == num2, "detected_count_num unchanged after 2nd VM::detect()");
        check(num1 == num3, "detected_count_num unchanged after 3rd VM::detect()");
    }

    std::cout << "\n=== VM::percentage() consistency ===\n";
    {
        const auto pct1 = VM::percentage();
        const auto pct2 = VM::percentage();
        const auto pct3 = VM::percentage();

        check(pct1 == pct2, "VM::percentage() 2nd call matches 1st");
        check(pct1 == pct3, "VM::percentage() 3rd call matches 1st");
    }

    std::cout << "\n=== VM::conclusion() consistency ===\n";
    {
        const std::string conc1 = VM::conclusion();
        const std::string conc2 = VM::conclusion();
        const std::string conc3 = VM::conclusion();

        check(conc1 == conc2, "VM::conclusion() 2nd call matches 1st");
        check(conc1 == conc3, "VM::conclusion() 3rd call matches 1st");
    }

    std::cout << "\n-----------\n";
    std::cout << "PASSED: " << pass_count << "\n";
    if (fail_count > 0) {
        std::cerr << "FAILED: " << fail_count << "\n";
    } else {
        std::cout << "FAILED: " << fail_count << "\n";
    }

    return (fail_count > 0) ? EXIT_FAILURE : EXIT_SUCCESS;
}
