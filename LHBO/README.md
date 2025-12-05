### Protocol for Heap Buffer Overflow.

To attempt to discover a heap buffer overflow, we must perform the following steps:

- First of all, a *Heap Buffer Overflow* affects the overflow of memory blocks in the heap, so the first thing we will do is identify these structures in the code, that is; any call to malloc/calloc/realloc or "wrappers" of these functions. These functions reserve a block of memory in the heap and return a pointer to the first address (or top) of the block.

- Subsequently, in reference to said call and the reserved memory block, we will stop to review the following questions:

    1. We will review whether the function (malloc, calloc, wrapper...) accepts or uses any parameter controlled by the user and if so, whether the parameter value has been correctly validated.

        For example, if we had:

        ```c
        int var = getuserdata();
        int* ptr = (int *) malloc(var);
        ```

        The size of the block reserved by *malloc()* could be as small as desired, any subsequent write operation in the code would be susceptible (if not correctly validated) to overwriting adjacent memory structures in the heap.

    2. On the other hand, we will review (as we did in the LSBO) data assignment or memory dump operations from one region to another such as:

        - "Weakly-bounded functions" like *memcpy()*, *sprintf()*, in which the destination of the dump is our memory region. These functions copy from a source to a destination a set of bytes, if this dump process is not regulated or if the set of bytes to be copied is somehow controlled by the user, it can result in an overwrite of adjacent structures.

        - Loops "for", "while", etc. in which additive assignment operations or of another nature are performed in our memory region. If the loop has a "break condition" controlled by the user, there is a possibility that the assignment operation will eventually overflow the memory region.

        Once such code structures are located, we will check if:

        1. There are possible restrictions or sanitization operations that can prevent the overflow. For example, an if statement that evaluates that the size of the data to be copied cannot be greater than the size of the destination structure.

        2. The source of the data is or is not controlled at some point in the path by the user.

        So that if there were a user-controlled data transfer operation on a fixed-size structure in the heap without restrictions, we would have a heap-buffer-overflow.

<br>

More information on the following [link](https://gsanmi1.github.io/2025-11-18-HBO/)

### Examples

Some examples could be:

```c
while (read_pos < length) { //length is user-controlled.
	c->operand[write_pos++] = msg[read_pos++]; //operand[] have 509 length.
	c->operand[write_pos++] = msg[read_pos++];
	c->operand[write_pos++] = msg[read_pos++];
	//...
```

