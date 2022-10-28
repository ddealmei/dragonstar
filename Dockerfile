FROM ubuntu:20.04

RUN apt update && \
	DEBIAN_FRONTEND="noninteractive" \
	apt install -y clang make vim python3 python3-pip python3-matplotlib python3-numpy libssl-dev linux-tools-generic linux-cloud-tools-generic sudo wget

# Build a NOASM Openssl for perf benchmarks
WORKDIR /tmp
RUN wget -O - -nv "https://www.openssl.org/source/openssl-1.1.1n.tar.gz" 2>/dev/null | tar xz > /dev/null

WORKDIR /tmp/openssl-1.1.1n
RUN ./config --prefix=/opt/local_install no-ssl2 no-tests -g3 -ggdb -gdwarf-4 no-asm 2>&1 >/dev/null
RUN make --quiet -j 2>/dev/null && make --quiet -j install_sw 2>&1 >/dev/null

# Create a user with access to sudo to avoid ACL conflicts in shared_folder
ARG user=poc_user
ARG group=poc_user
ARG uid=1000
ARG gid=1000
RUN groupadd -g ${gid} ${group}
RUN useradd -u ${uid} -g ${group} -s /bin/bash -m ${user} -p poc_user
RUN echo "${user} ALL=(ALL:ALL) NOPASSWD: ALL" > /etc/sudoers

COPY ./ /home/${user}/PoC/
WORKDIR /home/${user}/PoC/
RUN chown -R ${user}:${group} /home/${user}/PoC

USER ${uid}:${gid}

# Build Haclstar	
WORKDIR /home/${user}/PoC/haclstar/gcc-compatible
RUN	./configure
WORKDIR /home/${user}/PoC/
RUN make -C ./haclstar/gcc-compatible CC=clang -j libevercrypt.so
RUN ln -s /home/${user}/PoC/haclstar/kremlin/include/kremlin /home/${user}/PoC/haclstar/gcc-compatible/kremlin

# Build Dragonstar
WORKDIR /home/${user}/PoC/hostap/dragonstar
RUN make CONFIG_CRYPTO=hacl clean && make -j CONFIG_CRYPTO=hacl
RUN make CONFIG_CRYPTO=hacl CONFIG_PERF=y clean && make -j CONFIG_CRYPTO=hacl CONFIG_PERF=y
RUN make CONFIG_CRYPTO=openssl clean && make -j CONFIG_CRYPTO=openssl
RUN make CONFIG_CRYPTO=openssl CONFIG_PERF=y clean && make -j CONFIG_CRYPTO=openssl CONFIG_PERF=y
RUN make CONFIG_CRYPTO=openssl_noasm clean && make -j CONFIG_CRYPTO=openssl_noasm
RUN make CONFIG_CRYPTO=openssl_noasm CONFIG_PERF=y clean && make -j CONFIG_CRYPTO=openssl_noasm CONFIG_PERF=y

ENV HACL_PATH /home/poc_user/PoC/haclstar/gcc-compatible/
ENV LD_LIBRARY_PATH $HACL_PATH:$LD_LIBRARY_PATH
RUN echo $HACL_PATH | sudo tee /etc/ld.so.conf.d/hacl.conf && sudo ldconfig

WORKDIR /home/${user}/PoC/
