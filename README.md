# Project2-ParallelProgramming
Brute force parallelization using MPI

### Requirements
Use a VM that has Linux or use WSL if on windows.

### Install MPI
Open your terminal and run: <br>
```
sudo apt update
sudo apt install openmpi-bin libopenmpi-dev
``` 
<br>
To setup OpenSSL use: <br>
`sudo apt install openssl libssl-dev` 
<br>

Ideally use OpenSSL > 3.0. To check for the version you downloaded use:
`openssl version` 

### Compile
Compile code using: <br>
`mpicc -w bruteforce.c -o bruteforce -lcrypto`
And run using: <br>
`mpirun -np 4 bruteforce`