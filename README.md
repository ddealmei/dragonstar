# Dragonstar: A plugin verified cryptographic implementation for Dragonfly

The PAKE Dragonfly is used as SAE(-PT) in WPA3 authentication.

In this artifact, we rely on the NIST P-256 implementation in HaCl\*, which is written and verified as described in our paper (cf. Section 2.4 and Section 6.2). Relying on such implementation provides multiple guarantees, such as secret independence, memory safety, and full functional correctness.

Here, we provide the code generated from HaCl\* specification, to avoid the cumbersome process of generating it again from the specification (as it is done in HaCl\* repository). 

## Repository layout

We stress that we organized this artifact to be as easy as possible to test. Hence, we provide a Dockerfile that will build a container with all needed dependencies and compile the libraries and binaries as needed.

The most important folders are `scripts/` and `shared_folder/`, the other being used as part of the container build.

* `data/` contains a dictionary of passwords, used for both benchmarking and functional testing.
* `haclstar/` contains the C code from haclstar, with the additional modifications we did. This code can be compiled into a dynamic library.
* `hostap/` contains the C code from hostap v2.10 Release, with the additional modifications we did. 
* `scripts/` contains the scripts to run our tests: functional (by comparing outputs to OpenSSL) and performance are available.
* `shared_folder/` is used to share data (*e.g.* results from benchmarks) between the container and your host.

## Run the PoC

**Disclaimer** To provide a convenient way to test the code, we compare the value of important values between the execution of OpenSSL (used as reference) and our implementation. Since multiple values are randomly generated at each run, we replaced these values by valid constants when running in debug mode. These manipulations result in pieces of code such as 
```c
#ifdef DRAGONSTAR_DEBUG
	    memcpy(stub_password, password, password_len) < 0)
#else
	    random_get_bytes(stub_password, password_len) < 0)
#endif
```

We introduced the macro `DRAGONSTAR_DEBUG` to identify such cases.

### Setup the environment 

First, build the docker:
```bash
sudo docker build --rm -t dragonstar .
```

You can then run the docker (`--privileged` is only needed for the benchmark since `perf` requires specific capabilities):
```bash
sudo docker run --mount type=bind,source="$(pwd)"/shared_folder,target=/home/poc_user/PoC/shared_folder --privileged -it dragonstar
``` 

### Running experiments

Functional test by comparing outputs with OpenSSL's:
```
./scripts/differential_testing.sh
```

Benchmark our implementation against OpenSSL (as deployed on the system) and OpenSSL without assembly.
Since our benchmark relies on the `perf` tool, you may need to enable it on your host system with 
```
echo 0 | sudo tee /proc/sys/kernel/perf_event_paranoid
```
Then you can run the following in the docker container:

```bash
./scripts/perf_evaluation/bench.sh
```

This command will run the benchmark on 20 different passwords, repeating the handshake 1000 times for each password. It produces various PDF graphs comparing the performance of each library with different metrics (cycles, time and instructions).