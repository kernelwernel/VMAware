| File | Purpose |
|------|---------|
| `vmaware.hpp` | Official and original library header, most likely what you're looking for. |
| | |
| `cli/main.cpp` | CLI entry point and argument parsing |
| `cli/output.hpp` | Output formatting (general display and JSON) |
| `cli/strings.hpp` | ANSI color strings, argument enums, and global counters |
| `cli/types.hpp` | Shared primitive type aliases |
| `cli/sha256.hpp` | SHA-256 implementation used by the CLI |
| `cli/windows_tui.hpp` | Windows-specific ANSI support and string utilities |

<br>

> [!IMPORTANT]
> The main branch is much more updated with features that haven't been added yet to the latest release. However, they are experimental. 
> If you want something more stable, it's highly recommended to use the ones in the release section instead.
>
> On the other hand, testing the main branch version is advised so that feedback can be given back to make the library better.