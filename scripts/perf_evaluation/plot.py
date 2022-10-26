from sys import argv, exit
import matplotlib.pyplot as plt
import numpy as np

def process_file(f_name):
    # parse file into multiple datasets
    with open(f_name, 'r') as fp:
        lines = fp.readlines()

    y = []
    for l in lines:
        if l.startswith("#"):
            continue
        if float(l) < 10000000000000:
            y.append(float(l))
    if len(y) == 0:
        print("Something went wrong, we could get benchmarking information.")
        print("It is likely an issue with the availability of 'perf' within the container. You may need to install the correct version matching your host kernel version to make it work.") 
        print("You can run `pref` in the container to display the package you should install")
        exit(-1)
    return sum(y)/len(y)


if len(argv) < 2:
    print("Expecting a file name containing the data to plot")
    exit(-1)

d = {
    "legacy": [-1, -1, -1],
    "sswu": [-1, -1, -1],
}
for filename in argv[1:]:
    label = filename.split('-')[0].split('/')[-1]
    library = filename.split('-')[1].split('/')[-1].split('.')[0]
    avg = process_file(filename)
    if library == "openssl":
        d[label][0] = avg
    elif library == "hacl":
        d[label][1] = avg
    elif library == "openssl_noasm":
        d[label][2] = avg
    else:
        print("error", label)

x = np.arange(3)
width = 0.2
plt.bar(x-0.1, d["legacy"], width, color='orange', label="SAE")
plt.bar(x+0.1, d["sswu"], width, color='cyan', label="SAE-PT")
plt.xticks(x, ['OpenSSL', 'HaCl*', 'OpenSSL-noasm'])
plt.xlabel("Librairies")
plt.ylabel(argv[1].split('.')[1])

plt.title(f"{argv[1].split('.')[1]}", fontsize = 24)
plt.legend()

plt.savefig(f"shared_folder/graph_{argv[1].split('.')[1]}.pdf", format="pdf", dpi=1200)
