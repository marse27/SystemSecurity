To compile the tracer, run:

```bash
gcc -Wall -Wextra -std=c11 tracer.c -o tracer
```

Then execute the tracer on /bin/ls to record its system calls:
```bash
./tracer /bin/ls
```
