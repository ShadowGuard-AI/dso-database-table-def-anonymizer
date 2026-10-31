![Banner](banner.png)

# dso-database-table-def-anonymizer
Anonymizes database table definitions by replacing sensitive column names with generic ones (e.g., 'customer_name' becomes 'column_1'). Useful for sharing database schemas without revealing sensitive data structures. - Focused on Tools for sanitizing and obfuscating sensitive data within text files and structured data formats

By default, the pattern matches column names ending in `_name`, `_address`, `_phone`, `_email`, `_id`, `_number`, or `_hash`, camelCase names ending in `Name`, `Email`, `Phone`, or `Address`, and the standalone forms `ssn`, `credit_card`, `date_of_birth`, `password`, `name`, `email`, and `phone`. Use `--column_name_pattern` to supply a different pattern. Each distinct column name gets one generic replacement, reused at every occurrence.

The tool refuses, at exit 1, when the output path resolves to the input file (the same path, a `./` alias, or a symlink). A run that replaces no column names also exits 1 and writes no output.

## Install
`git clone https://github.com/ShadowStrikeHQ/dso-database-table-def-anonymizer`

## Usage
`./dso-database-table-def-anonymizer [params]`

## Parameters
- `-h`: Show help message and exit
- `--column_name_pattern`: No description provided
- `--column_prefix`: Prefix for anonymized column names (e.g., 
- `--encoding`: Character encoding of the input file. Defaults to 

## License
Copyright (c) ShadowStrikeHQ
