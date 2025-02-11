#!/usr/bin/env python3

# Generate byte arrays from strings.

import sys


def main():
    if len(sys.argv) < 2:
        print(f"{sys.argv[0]} strings...")
        return

    for arg in sys.argv[1:]:
        array = ", ".join([f"'{c}'" for c in list(arg)])
        src = "{ " + array + " }"
        print(src)


if __name__ == "__main__":
    main()
