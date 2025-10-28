#!/bin/bash

# A script to generate a function tracing configuration file for funclatency.
# It intelligently filters out common library/runtime functions and comments
# out all entries by default, making it easy for users to select functions
# to trace.

# --- Configuration: Keywords to filter out ---
# This is a grep extended regular expression pattern.
# Each part is separated by a pipe `|`.
FILTER_PATTERN=(
    # C++ Standard Library
    "std::"
    "__gnu_cxx::"

    # --- NEW: Add Boost library namespace here ---
    "boost::"
    
    # Common C library and runtime functions
    "^_start"
    "^__libc_"
    "^register_tm_clones"
    "^deregister_tm_clones"
    "^__do_global_"
    "^_dl_relocate_static_pie"
    "^_GLOBAL__sub_I_"

    # Dynamic linking stubs and other noise
    "@plt"
    "\\(clone \\w+\\)$" # Matches GCC clone functions like `(clone .cold)`
    
    # Add any other patterns you want to ignore here
    # "Qt::"
    # "folly::"
)

# --- Main Script Logic (unchanged) ---

# Check for input argument
if [ "$#" -ne 1 ]; then
    echo "Usage: $0 /path/to/your/binary"
    echo "Description: Generates a config file with all user-defined functions commented out."
    exit 1
fi

BINARY_PATH=$1

# Check if the binary exists and is not a directory
if [ ! -f "$BINARY_PATH" ]; then
    echo "Error: File not found: $BINARY_PATH"
    exit 1
fi
if [ ! -x "$BINARY_PATH" ]; then
    echo "Warning: File is not executable: $BINARY_PATH"
fi


# Check if nm tool is available
if ! command -v nm &> /dev/null; then
    echo "Error: 'nm' command not found. Please install binutils."
    exit 1
fi

# Build the final filter pattern for grep
# This joins all elements of the FILTER_PATTERN array with a pipe `|`
FILTER_GREP_PATTERN=$(IFS="|"; echo "${FILTER_PATTERN[*]}")

# Process the binary with nm
# 1. Get demangled names to apply the filter.
# 2. For the matching lines, find their original mangled names.
# 3. Format and print the output.

echo "#"
echo "# Configuration file for funclatency"
echo "# Generated on $(date) for binary: $BINARY_PATH"
echo "#"
echo "# To trace a function, simply remove the '#' character from the beginning of its line."
echo "# Format: <address> <mangled_name> <demangled_name>"
echo "#"
echo

# We use process substitution and join to do this in a single pass
# This is more efficient than calling nm multiple times.
join \
    <(nm -p "$BINARY_PATH" 2>/dev/null | grep -E ' (T|t|W|w) ' | awk '{print $1 " " $3}') \
    <(nm -p -C "$BINARY_PATH" 2>/dev/null | grep -E ' (T|t|W|w) ' | awk '{addr=$1; $1=""; $2=""; print addr " " substr($0, 3)}') \
    | grep -v -E "$FILTER_GREP_PATTERN" \
    | awk '{print "# " "0x"$1 " " $2 " " substr($0, length($1)+length($2)+3)}' \
    | sort -k 4 # Sort by the demangled name for easier reading