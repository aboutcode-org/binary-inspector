Changelog
=========

v0.2.0
------

Minor release with updated dependencies and python support.

v0.1.2
------

Bugfix release to fix click compatibility issues:

* Update commoncode to latest v32.3.0 with click compatibility fixes


v0.1.1
------

Bugfix release as the intial release had empty wheels:

* Fix binary-inspector wheels to have the necessary modules.
* Update to latest skeleton


v0.1.0
------

Initial release with support for:

* Get parsed list of demangled and cleaned symbols from a winpe binary
* Get parsed list of demangled and cleaned symbols from a macho binary
* scancode-toolkit plugins for collecting symbols from macho and winpe binaries
  with the CLI option --winpe-symbol --macho-symbol
