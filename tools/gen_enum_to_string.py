f = open("src/network/protocols/tcp.h")



enum_name = input("Enter the exact enum name only:\n:>")

lines = []
add_attributes = False
for line in f:
    if "};" in line and add_attributes:
        add_attributes = False
        break
    if add_attributes:
        lines.append(line[:line.index("=") if "=" in line else -1].lstrip().rstrip().replace("\n", "").replace(",", ""))

    if f"enum class {enum_name}" in line or f"enum {enum_name}" in line:
        add_attributes = True



outputfile = open(f"enum_{enum_name}_tostring.cpp", mode="w+")


outputstring = ""
outputstring += f"const char* get_{enum_name}_as_string({enum_name} val) {{\n"
outputstring += f"    switch (val) {{\n"
for line in lines:
    outputstring += f"        case {enum_name}::{line} : {{\n            return \"{line}\";\n        }}\n"


outputstring += f"        default : {{\n            return 0;\n        }}\n"
outputstring += f"    }}\n"
outputstring += f"}}"

outputfile.write(outputstring)