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

### Compile
Compile code using: <br>
`mpicc bruteforce.c -o bruteforce -lcrypto`
And run using: <br>
`mpirun bruteforce`