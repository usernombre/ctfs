#!/usr/bin/env python3

binary_path = "./vault.elf"

# Common information extracted from the main function
flag_path = "flag.txt"
flag_length = 0x19


def solve_static():
    import pwn

    # Information extracted from the main function
    indices_address = 0xE090
    pointer_array_address = 0x17880
    pointer_array_length = 0x100

    # Load the binary and initialize the pwntools context
    pwn.context.binary = binary = pwn.ELF(binary_path)

    # The flag is encoded as indices into an array of chained pointers to routines,
    # which return the real value when executed
    indices = binary.read(indices_address, flag_length)
    pointer_array = [
        pwn.u64(binary.read(pointer_array_address + 8 * i, 8))
        for i in range(pointer_array_length)
    ]

    flag = ""
    for i in range(flag_length):
        # Fetch the pointer and perform two indirections
        pointer = pointer_array[indices[i]]
        pointer = pwn.u64(binary.read(pointer, 8))
        pointer = pwn.u64(binary.read(pointer, 8))
        # Routines all have the same layout, so simply grab the return value
        #   0:   55                      push   rbp
        #   1:   48 89 e5                mov    rbp, rsp
        #   4:   48 89 7d f8             mov    QWORD PTR [rbp-0x8], rdi
        #   8:   b0 ??                   mov    al, 0x??
        #   a:   0f b6 c0                movzx  eax, al
        #   d:   5d                      pop    rbp
        flag += chr(binary.read(pointer, 0xE)[9])

    return flag


def solve_dynamic():
    import pathlib

    import pwn

    # Default load address for 64-bit PIE Linux executables when ASLR is disabled
    # https://stackoverflow.com/q/51343596
    base_address = 0x555555554000
    # Instruction address where the plaintext value of the flag is available in the AL register
    plaintext_address = base_address + 0xC37A

    # Write a fake flag with a valid length so that all comparisons are executed
    flag_file = pathlib.Path(flag_path)
    flag_file.write_text("A" * flag_length)

    # Start debugging the binary and set a breakpoint at plaintext_address
    io = pwn.gdb.debug(binary_path, aslr=False, api=True)
    io.gdb.Breakpoint(f"*{plaintext_address}")

    flag = ""
    for i in range(flag_length):
        # Continue execution until the breakpoint is hit and read the next byte of the flag
        io.gdb.continue_and_wait()
        al = io.gdb.newest_frame().read_register("al")
        flag += chr(al)

    flag_file.unlink()
    return flag


# Based on https://github.com/angr/angr-examples/blob/master/examples/asisctffinals2015_license/solve.py
def solve_symbolic():
    import angr
    import claripy

    # Default load address for angr binaries
    base_address = 0x400000
    # First address of branch printing success message
    find_address = base_address + 0xC3D1
    # First address of branch printing failure message
    avoid_address = base_address + 0xC3A9

    # Create a project and a state at the entrypoint
    # Could be made faster by disabling auto_load_libs and defining custom hooks for C++ functions
    project = angr.Project(binary_path, auto_load_libs=True)
    state = project.factory.entry_state()

    # Insert a symbolic representation of the flag into the angr filesystem
    flag_vector = claripy.Concat(
        *[claripy.BVS(f"flag_{i}", 8) for i in range(flag_length)]
    )
    flag_file = angr.storage.file.SimFile(flag_path, flag_vector)
    state.fs.insert(flag_path, flag_file)

    # Create a simulation manager that explores states until a terminating address is found
    simulation = project.factory.simulation_manager(state)
    simulation.explore(find=find_address, avoid=avoid_address)

    # Assert that a valid state was found and use it to evaluate the flag
    assert simulation.found
    flag = simulation.found[0].solver.eval(flag_vector, cast_to=bytes).decode()
    return flag


def main():
    import argparse
    import time

    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-a",
        "--approach",
        choices=["static", "dynamic", "symbolic"],
        default="static",
        help="solving approach (default: %(default)s)",
    )
    args = parser.parse_args()

    print(f"Solving using {args.approach} approach")
    start_time = time.perf_counter()

    if args.approach == "static":
        flag = solve_static()
    elif args.approach == "dynamic":
        flag = solve_dynamic()
    elif args.approach == "symbolic":
        flag = solve_symbolic()

    end_time = time.perf_counter()
    execution_time = end_time - start_time
    print(f"Solved in {execution_time:.6f} seconds")
    print(f"Flag: '{flag}'")


if __name__ == "__main__":
    main()
