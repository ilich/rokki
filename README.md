# rokki

[![Build Status](https://travis-ci.org/ilich/rokki.svg?branch=master)](https://travis-ci.org/ilich/rokki)

Rokki is a simple websites malware scanner insiped by [Manul Antimalware Tool](https://github.com/antimalware/manul/). The tool has been developed to help system administrators to find malware in websites without a need to install PHP on the server.

## Installation

Run `npm install -g rokki` in your terminal

## Usage

`rokki [options] [file/directory]`

**Options**:

* `-h, --help` - output usage information
* `-V, --version` - output the version number
* `-v, --verbose` - be verbose
* `-r, --recursive` - scan directories recursively. All the subdirectories in the given directory will be scanned
* `-l, --log <file>` - save scan report to #file.
* `--json` - save scan report in JSON format.
* `--exclude <regex>` - don't scan file names matching regular expression.
* `--exclude-dir <regex> ` - don't scan directory names matching regular expression.
* `--include <regex>` - only scan file matching regular expression.
* `--include-dir <regex>` - only scan directory matching regular expression.
* `--max-filesize <n>` - scan files with size at most #n kilobytes (default: 100 MB)

## Warning

This tool does not have auto-update mechanism. Please make sure you have the latest NPM package installed.

## Credits

* [Manul Antimalware Tool](https://github.com/antimalware/manul/) by Peter Volkov (peter.r.volkov@yandex.ru) and Greg Zemskov (ai@revisium.com)
* [w3af](http://w3af.org/) by Andres Riancho and [contributors](https://github.com/andresriancho/w3af/blob/master/doc/CONTRIBUTORS).
* [Bar4mi WebShell Finder](https://code.google.com/p/bwsfinder/) by Simon Ryeo (bar4mi@gmail.com)  