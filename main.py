import argparse
import logging
import os
import sys
import re
import chardet  # For character encoding detection

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


def setup_argparse():
    """
    Sets up the argument parser for the command-line interface.
    Returns:
        argparse.ArgumentParser: The configured argument parser.
    """
    parser = argparse.ArgumentParser(
        description="Anonymizes database table definitions by replacing sensitive column names with generic ones."
    )
    parser.add_argument(
        "input_file",
        help="The path to the input file containing the database table definition."
    )
    parser.add_argument(
        "output_file",
        help="The path to the output file to write the anonymized table definition."
    )
    parser.add_argument(
        "--column_name_pattern",
        default=r'\b(\w+_name|\w+_address|\w+_phone|\w+_email|\w+_id|\w+_number|\w+_hash|\w+(?:Name|Email|Phone|Address)|ssn|credit_card|date_of_birth|password|name|email|phone)\b',
        help="Regex pattern to identify sensitive column names.  Defaults to common patterns.",
    )
    parser.add_argument(
        "--column_prefix",
        default="column_",
        help="Prefix for anonymized column names (e.g., 'column_'). Defaults to 'column_'"
    )
    parser.add_argument(
        "--encoding",
        default="utf-8",
        help="Character encoding of the input file. Defaults to 'utf-8'.  Use 'auto' to attempt automatic detection."
    )

    return parser


def anonymize_table_definition(input_file, output_file, column_name_pattern, column_prefix, encoding="utf-8"):
    """
    Anonymizes a database table definition by replacing sensitive column names with generic ones.

    Args:
        input_file (str): Path to the input file containing the table definition.
        output_file (str): Path to the output file to write the anonymized definition.
        column_name_pattern (str): Regex pattern to identify sensitive column names.
        column_prefix (str): Prefix for anonymized column names.
        encoding (str): Character encoding of the input and output files.
    """

    # Refuse in place output: resolved equality covers the same string,
    # a ./ alias, and a symlink pointing at the input.
    if os.path.realpath(input_file) == os.path.realpath(output_file):
        logging.error("Error: Output file resolves to the input file; refusing to overwrite the input.")
        sys.exit(1)

    try:
        # Determine encoding if 'auto' is specified
        if encoding.lower() == 'auto':
            with open(input_file, 'rb') as f:  # Open in binary mode for detection
                rawdata = f.read()
                result = chardet.detect(rawdata)
                encoding = result['encoding']
                logging.info(f"Detected encoding: {encoding}")
                if encoding is None:
                    raise ValueError("Unable to automatically detect file encoding.")

        # errors='replace' means bytes that do not decode become the
        # replacement character in the output rather than an error, so a
        # file in the wrong encoding is rewritten with silent damage in
        # places that have nothing to do with column names.
        with open(input_file, "r", encoding=encoding, errors='replace') as infile:
            table_definition = infile.read()

        # Anonymize column names using regex. Each distinct name gets one
        # replacement, reused at every occurrence: a name usually appears
        # again outside its definition (an index, a foreign key), and the
        # old per match counter renamed those later occurrences to a
        # different column, breaking the definition it was meant to hide
        # in plain sight.
        replacements = {}
        def replace_column_name(match):
            key = match.group(0).lower()
            if key not in replacements:
                replacements[key] = f"{column_prefix}{len(replacements) + 1}"
            return replacements[key]

        # Nothing parses the SQL: the substitution runs over the raw text
        # of the whole file. I verified both consequences. A keyword inside
        # a string literal is replaced like a column name, so a default of
        # 'contact email here' comes out as 'contact column_2 here', a data
        # change wearing a schema change's clothes; and because matching
        # is case-insensitive with the key lowercased below, user_id and
        # User_ID are unified into one replacement. Numbering follows
        # first appearance in the text, not the table's column order alone:
        # a name first met in a comment or an index numbers before a name
        # first met in its own definition.
        anonymized_definition = re.sub(column_name_pattern, replace_column_name, table_definition, flags=re.IGNORECASE)  # Consider case-insensitive matching

        # A run that replaced nothing has not anonymized anything: fail
        # without writing output or claiming success.
        if not replacements:
            logging.error("Error: No column names matched the pattern; nothing was anonymized.")
            sys.exit(1)

        # Write the anonymized definition to the output file
        with open(output_file, "w", encoding=encoding) as outfile:
            outfile.write(anonymized_definition)

        logging.info(f"Anonymized table definition written to {output_file}")

    except FileNotFoundError:
        logging.error(f"Error: Input file '{input_file}' not found.")
        sys.exit(1)
    except IOError as e:
        logging.error(f"IOError: {e}")
        sys.exit(1)
    except re.error as e:
        logging.error(f"Regex Error: Invalid regular expression: {e}")
        sys.exit(1)
    except ValueError as e:
        logging.error(f"ValueError: {e}")
        sys.exit(1)
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")
        sys.exit(1)


def main():
    """
    Main function to parse arguments and call the anonymization function.
    """
    parser = setup_argparse()
    args = parser.parse_args()

    # Input validation (basic check to prevent empty filenames)
    if not args.input_file or not args.output_file:
        logging.error("Error: Input and output file paths must be specified.")
        parser.print_help()
        sys.exit(1)

    try:
        anonymize_table_definition(args.input_file, args.output_file, args.column_name_pattern, args.column_prefix, args.encoding)
    except Exception as e:
        logging.error(f"An error occurred: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()


"""
Usage Examples:

1.  Basic usage:  Anonymize input.sql and write to output.sql using the default pattern and prefix:
    python dso-database-table-def-anonymizer.py input.sql output.sql

2.  Specify a custom column name pattern:
    python dso-database-table-def-anonymizer.py input.sql output.sql --column_name_pattern "ssn|credit_card"

3.  Specify a custom column prefix:
    python dso-database-table-def-anonymizer.py input.sql output.sql --column_prefix "renamed_column_"

4.  Specify a different character encoding:
    python dso-database-table-def-anonymizer.py input.sql output.sql --encoding "latin-1"

5. Attempt automatic detection of character encoding:
    python dso-database-table-def-anonymizer.py input.sql output.sql --encoding "auto"

Example input.sql:
CREATE TABLE Customers (
    customer_id INT PRIMARY KEY,
    customer_name VARCHAR(255),
    customer_address VARCHAR(255),
    customer_phone VARCHAR(20),
    customer_email VARCHAR(255)
);

Example output.sql (using defaults):
CREATE TABLE Customers (
    column_1 INT PRIMARY KEY,
    column_2 VARCHAR(255),
    column_3 VARCHAR(255),
    column_4 VARCHAR(20),
    column_5 VARCHAR(255)
);

"""