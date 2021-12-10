dangerous_functions = [
    "strcpy",
    "strcat",
    "sprintf",
    "read",
    "getenv"
]

attention_function = [
    "memcpy",
    "strncpy",
    "sscanf",
    "strncat",
    "snprintf",
    "vprintf",
    "printf"
]

command_execution_function = [
    "system",
    "execve",
    "popen",
    "unlink"
]

# describe arg num of function

one_arg_function = [
    "getenv",
    "system",
    "unlink"
]

two_arg_function = [
    "strcpy",
    "strcat",
    "popen"
]

three_arg_function = [
    "strncpy",
    "strncat",
    "memcpy",
    "execve",
    "read"
]

format_function_offset_dict = {
    "sprintf":1,
    "sscanf":1,
    "snprintf":2,
    "vprintf":0,
    "printf":0
}
regs = ["di", "si", "dx", "cx", "8", "9"]