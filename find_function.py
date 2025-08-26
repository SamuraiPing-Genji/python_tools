import subprocess
import re
import sys
from collections import defaultdict, deque

# binary = "/home/os-isaac.fang/Desktop/weirdo_fuzzer/benchmarks/vorbis/vorbis"  # binary 路徑
check_human = 0

binary = "/home/os-isaac.fang/Desktop/weirdo_fuzzer/benchmarks/magma-libpng/magma-libpng"  # binary 路徑

def get_function_address(func_name):
    cmd = [
        "gdb", "-batch", "-ex", f"file {binary}",
        "-ex", f"info address {func_name}"
    ]
    try:
        output = subprocess.check_output(cmd, text=True, stderr=subprocess.DEVNULL)
    except subprocess.CalledProcessError as e:
        # raise RuntimeError("command '{}' return with error (code {}): {}".format(e.cmd, e.returncode, e.output))
        return None
    match = re.search(r"0x[0-9a-fA-F]+", output)
    return match.group(0) if match else None

def get_function_symbol(addresses):
    symbol_list = set()
    for addr in addresses:
        # print(f"addr: {addr}")
        cmd = [
            "gdb", "-batch", "-ex", f"file {binary}",
            "-ex", f"info symbol {addr}"
        ]
        try:
            output = subprocess.check_output(cmd, text=True, stderr=subprocess.DEVNULL)
        except subprocess.CalledProcessError:
            continue

        output = output.strip()
        if output.startswith("No symbol"):
            continue
        
        
        symbol = output.split(" ")[0]
        symbol = symbol.split("(")[0] # 有些 info symbol 會出現 function_name(char...)
        # print(f"[+] {addr} -> {symbol}")
        symbol_list.add(symbol)
    return symbol_list


def objdump_handler(address):
    cmd = ["objdump", "-d", binary]
    output = subprocess.check_output(cmd, text=True)  
    call_function_addr = set()
    global check_human
    for line in output.splitlines():
        if address[2:] in line and "#" in line:
            check_human = 1
            call_function_addr.add(f"0x{line.split(':')[0][2:]}".replace(" ", ""))
        elif address[2:] in line and "call" in line:
            call_function_addr.add(f"0x{line.split(':')[0][2:]}".replace(" ", ""))
    return call_function_addr




def run_to_run(target_func, black_list):
    print(f"target_function: {target_func}")
    
    black_list[target_func] = 1
    addr = get_function_address(target_func)
    if not addr:
        print(f"[!] 找不到 {target_func}")
        sys.exit(1)
    # print(f"    {target_func} 位址: {addr}")
    call_function_addr = objdump_handler(addr)
    # print(f"function_addr: {call_function_addr}")
    symbol_function = get_function_symbol(call_function_addr)
    print(f"symbol_function: {symbol_function}")
    
    for i in list(symbol_function):
        if not black_list.get(i, 0):
            # print(f"Is {i} in black_list? Ans: {i in black_list}")
            # print(f"black_list: {black_list}")
            black_list[i] = 1
            
            print("--------------------------------------")
            run_to_run(i, black_list)
    return black_list
    

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(f"用法: {sys.argv[0]} <magma-benchmark> <target_function>")
        sys.exit(1)


    binary = f"/home/os-isaac.fang/Desktop/weirdo_fuzzer/benchmarks/magma-{sys.argv[1]}/magma-{sys.argv[1]}"
    if 'vorbis' in sys.argv[1]:
        binary = f"/home/os-isaac.fang/Desktop/weirdo_fuzzer/benchmarks/{sys.argv[1]}/{sys.argv[1]}.afl"
    target_func = sys.argv[2]

    print(f"[*] 找有調用 {target_func} 的function...")
    black_list = run_to_run(target_func, {})
    question = 'main can touch function?'
    print(f"{question} Ans: {'LLVMFuzzerTestOneInput' in black_list}")
    print(f"human_check? Ans: {check_human}")
    with open(f"{sys.argv[1]}_{sys.argv[2]}.txt", "+w") as f:
        f.write(''.join(f"{i}\n" for i in black_list))
        print(f"Black_list write to {sys.argv[1]}_{sys.argv[2]}.txt")
    # print(f"black_list: {black_list}")
    