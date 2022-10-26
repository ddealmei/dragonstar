from sys import argv

# This reflects the value of the macro in main.c
N_TESTS=1000

for filename in argv[1:]:
    with open(filename, 'r') as fp:
        data = fp.readlines()
        cycles = []
        instructions = []
        time = []
        ins_per_cycle = []
        i = 0
        for line in data:
            line = line.lstrip()
            if "seconds time elapsed" in line:
                t = float(line.split('+')[0].split(' ')[0].replace(',', '.'))
                time.append(str(t/N_TESTS)+'\n')
                ins_per_cycle.append(
                    str(float(instructions[i]) / float(cycles[i]))+'\n')
                i += 1
                continue
            if "cycles" in line:
                c = float(line.split('      ')[
                              0].replace('\u202f', ''))
                cycles.append(str(c/N_TESTS)+'\n')
            elif "instructions" in line:
                ins = float(line.split('      ')[0].replace('\u202f', ''))
                instructions.append(
                    str(ins/N_TESTS)+'\n')
    with open(filename.replace("perf", "cycles"), 'w') as fp:
        fp.writelines(cycles)
    with open(filename.replace("perf", "time"), 'w') as fp:
        fp.writelines(time)
    with open(filename.replace("perf", "instructions"), 'w') as fp:
        fp.writelines(instructions)
    with open(filename.replace("perf", "ins_per_cycle"), 'w') as fp:
        fp.writelines(ins_per_cycle)
