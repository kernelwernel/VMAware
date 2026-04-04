# VMAware-rb

_A `ruby` wrapper for VMAware._

## Notes
- The gem is not supported on windows.
- Builds a native gem.
- Only exports two functions: `vm?` (`VM::detect`) and `confidence`(`VM::percentage`) in their default invocation.

> If building under `gem install vmaware-rb` starts complaining about a missing `make install` step, update your rubygems (`gem update --system`).