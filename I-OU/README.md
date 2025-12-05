### Integer Overflow/Underflow Protocol

We refer to Integer Overflow/Underflow as a set of code defects related to mathematical operations performed with integers and user-controlled data.

Any datatype in C has a finite range of values and exists within a ring of values mod N (where N is the bit width the value can take). This means that an integer variable (char, short, int, etc.) can keep taking increasingly larger/smaller values until it crosses a threshold (2^N) and goes from being the largest/smallest possible value to the smallest/largest possible one, only to grow/shrink again. When this happens, we call it Integer Overflow/Underflow.

This can occur mainly in two ways; we distinguish between:

- **Signed Integers**, which change sign when the threshold is crossed (passing through 0 as they increment):

    ```less
        0, +1, +2, +3 (positive) MAX_SIZE --> Overflow --> MIN_SIZE (negative) -3, -2, -1, 0 -->
        -1, -2, -3 ... (negative) MIN_SIZE --> Underflow --> MAX_SIZE (positive) +3, +2, +1, 0 -->
    ```

- **Unsigned Integers**, which are expressed in absolute values, changing from the largest value to 0 and viceversa:

    ```less
        0, 1, 2, ... MAX_SIZE --> Overflow --> 0, 1, 2...
        3, 2, 1, 0 --> Underflow --> MAX_SIZE ... 3, 2, 1 
    ```

<br>

Therefore, when auditing code we are primarily interested in detecting any mathematical operation involving user-controlled data in the code. 

For example, if VAR is user-controlled data, then:

```less
data1 = VAR + A: VAR (large) --> VAR + A > MAX_SIZE --> data1 (Overflow, small due to wrap)
data2 = VAR - B: VAR (small) --> VAR - B < 0 --> data2 (Underflow, big due to wrap)
```

The risk does not lie in the fact that these thresholds are crossed, but in what is done with the data once the results are produced and stored. That is, an integer overflow can result in a heap memory under-allocation that could lead to a buffer overflow. Consider the following example code:

```c
data1 = VAR + A;
data2 = VAR - B;

char* cptr = (char*) malloc(data1); // data1 (Overflowed, small) --> cptr points to a very small allocated memory region.
memcpy(cptr, someBuffer, data2);   // data2 (Underflowed, large) --> memcpy is copying data2 (a very large value) from buffer to cptr (a very small memory block).
```

In summary:

- Check whether mathematical operations involving user data exist and whether any sanitization is performed before or after the operation.
- Observe what is done with the results of these operations and whether they could corrupt the code execution flow. Pay particular attention to under-allocations or over-copies as illustrated in the case above.

More information on the following [link](https://gsanmi1.github.io/2025-12-05-IntegerOverflow-Underflow/)
<br>

### Examples

As an example, we have the following C code:
```c
////ACID: The data read from staFileHandler
FILE *staFileHandler; //File handler is valid and already points to 0x200 location 
                      //in .sta file being loaded.
size_t x;
size_t y;
size_t allocSize;
void *memoryAllocation;

fread(&x, 4, 1, staFileHandler);
fread(&y, 4, 1, staFileHandler);
allocSize = y - x;
memoryAllocation = VirtualAlloc(0, allocSize, 0x3000, 4);
fread(memoryAllocation + x, 1, allocSize, staFileHandler);
```

Recall that fread() reads and stores data into a variable from a file descriptor, and as it reads, it advances the file descriptor.