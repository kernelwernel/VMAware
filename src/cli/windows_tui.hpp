#pragma once

#include <iostream>
#include <sstream>

#if (CLI_WINDOWS)
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX

#include <windows.h>
#include <winternl.h>
#include <intrin.h>
#include <mutex>
#include <deque>
#include <conio.h>
#include <iomanip>
#include <vector>
#include <string>

#include "globals.hpp"
#include "sha256.hpp"

#pragma comment(lib, "ntdll.lib")

    class win_ansi_enabler_t
    {
    public:
        win_ansi_enabler_t() : m_set(FALSE), m_old(0), m_out(GetStdHandle(STD_OUTPUT_HANDLE))
        {
            if (m_out != nullptr && m_out != INVALID_HANDLE_VALUE) {
                if (GetConsoleMode(m_out, &m_old) != FALSE) {
                    m_set = SetConsoleMode(m_out, m_old | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
                }
            }
        }
        ~win_ansi_enabler_t() {
            if (m_set != FALSE) {
                SetConsoleMode(m_out, m_old);
            }
        }
    private:
        win_ansi_enabler_t(win_ansi_enabler_t const&) = delete;
        bool m_set;
        DWORD m_old;
        HANDLE m_out;
    };

    // safely trims and pads a string ensuring it fits perfectly within bounds
    // without leaking unclosed ANSI tags or overflowing text visually
    inline std::string pad(const std::string& str, size_t target_len) {
        size_t vlen = 0;
        bool in_ansi = false;
        std::string result;
        for (char c : str) {
            if (c == '\x1B') {
                in_ansi = true;
            }

            if (!in_ansi) {
                if (vlen < target_len) {
                    result += c;
                    vlen++;
                }
            } else {
                result += c;
                if (c == 'm') {
                    in_ansi = false;
                }
            }
        }

        if (vlen < target_len) {
            result += std::string(target_len - vlen, ' ');
        }

        if (vlen >= target_len) {
            result += "\x1B[0m"; // ensure sequences are closed if string gets sliced
        }

        return result;
    }

    inline size_t visible_length(const std::string& str) {
        size_t len = 0;
        bool in_ansi = false;
        for (char c : str) {
            if (c == '\x1B') {
                in_ansi = true;
            } else if (in_ansi && c == 'm') {
                in_ansi = false;
            } else if (!in_ansi) {
                len++;
            }
        }
        return len;
    }

    inline std::string repeat_str(const std::string& str, size_t count) {
        std::string res;
        res.reserve(str.length() * count);
        for (size_t i = 0; i < count; ++i) {
            res += str;
        }
        return res;
    }

    // UI Manager: Dynamic scaling boxes with aggressive dark/white sync theme
    class TuiManager {
    public:
        SHORT start_y = 0;
        SHORT left_y = 0;
        SHORT right_x = 0;
        SHORT left_margin = 0;
        SHORT console_width = 120;

        SHORT exception_y = 0;
        SHORT box_height = 10;
        size_t global_box_width = 70; // dynamic base width

        HANDLE hOut = nullptr;
        std::mutex mtx;
        bool enabled = false;

        std::streambuf* orig_buf = nullptr;
        std::ostream* raw_out = nullptr;

        std::vector<std::vector<std::string>> exceptions;
        size_t exc_scroll_index = 0;

        std::vector<std::string> cycles;
        size_t cyc_scroll_index = 0;

        std::vector<std::string> debugs;
        size_t dbg_scroll_index = 0;

        u32 g_max_std = 0;
        u32 g_max_hyp = 0;
        u32 g_max_ext = 0;

        bool setCursorSafe(SHORT x, SHORT y);
        bool updateBoxWidth(size_t incoming_len);
        void init();
        ~TuiManager();
        void printHeader();
        void printLeft(const std::string& str);
        void clearBoxes();
        void redrawAllBoxes();
        SHORT drawBoxInternal(SHORT startY, size_t box_width, const std::string& title, const std::vector<std::string>& items, size_t scroll_idx, const std::string& controls);
        void addException(const std::vector<std::string>& lines);
        void addCycle(const std::string& line);
        void addDebug(const std::string& line);
        void scrollExceptionsUp();
        void scrollExceptionsDown();
        void scrollCyclesUp();
        void scrollCyclesDown();
        void scrollDebugUp();
        void scrollDebugDown();
        void drawSummaryBox(const std::vector<std::string>& lines);
        void finalize();
    };

    extern TuiManager g_tui;

    // Aggressive stream interceptor. ALL output sent through std::cout that doesn't explicitly bypass
    // into g_tui.raw_out gets captured and sent to the Debug Log UI. No layout escapes possible
    class DebugInterceptor : public std::streambuf {
        std::string buffer;
    public:
        std::streambuf* original;

        DebugInterceptor(std::streambuf* orig) : original(orig) {}
        ~DebugInterceptor();
    protected:
        virtual int_type overflow(int_type c) override;
        virtual std::streamsize xsputn(const char* s, std::streamsize n) override;
    };

    #define PRINT_LINE(msg) \
        do { \
            std::ostringstream _oss; \
            _oss << msg; \
            g_tui.printLeft(_oss.str()); \
        } while(0)

    template<typename... Args>
    void VMAWARE_CLI_DEBUG(Args&&... args) {
        std::ostringstream oss;
        int dummy[] = { 0, ((void)(oss << args), 0)... };
        (void)dummy;
        std::cout << "[DEBUG] " << oss.str() << "\n";
    }

    LONG WINAPI VehLogger(PEXCEPTION_POINTERS ep);

#else

    #define PRINT_LINE(msg) std::cout << (msg) << "\n"

    template<typename... Args>
    void VMAWARE_CLI_DEBUG(Args&&... args) {
        std::ostringstream oss;
        int dummy[] = { 0, ((void)(oss << std::forward<Args>(args)), 0)... };
        (void)dummy;
        std::cout << "[DEBUG] " << oss.str() << "\n";
    }

#endif