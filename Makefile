all: tarball_incremental

tarball_incremental: tarball_incremental.c
	gcc -o tarball_incremental tarball_incremental.c -I/usr/local/opt/libarchive/include -ldl
