### Protocol for Uninitialized Data Access.

#### Definition.

The UDA vulnerability consists of reading from an object that has not been assigned a value previously.

The basis of the risk lies in how memory is managed in a running program. Memory usage in a running program is dynamic; parts of that memory are constantly entering and leaving use, so many blocks are recycled by overwriting their contents with new data.

Information written to a memory block is not erased when it is freed and remains accessible until the program overwrites that data or terminates.

Therefore, when declaring a variable it occupies a place in memory and there is a risk that the data can be read if the variable is not initialized before being used.

<br>

#### Examples.

Classic Vulnerable Patterns:

1. **Uninitialized Local Variable, allocated on the stack**:

    ```c
    int vulnerable(int condition) {
        int result;              //stack-garbage
        
        if (condition > 0) {
            result = do_something();
        }
        // if condition <= 0, result is never assigned
        
        return result;           // Potential UDA
    }
    ```

    In the code above, a variable is not initialized and is returned to the program's execution flow. If that variable were read, the stack "garbage" where that variable resides would be read.

    <br>

2. **Stack Buffer**: 

    ```c
    void vulnerable(void) {
        char buffer[256];        // 256 bytes of garbage
        
        int n = read(fd, buffer, 100);
        
        send(sock, buffer, 256, 0);  // sends 156 uninitialized bytes
    }
    ```
    In the example above, part of the buffer is not initialized. If it were eventually included within a poorly regulated iterative loop, uninitialized memory contents would eventually be used.

    <br>
    
3. **Partially Initialized Struct**:

    The following code presents a classic example: a structure that is partially initialized and subsequently parts of that structure are used without being initialized.

    ```c
    struct config {
        int mode;
        int flags;
        char *path;
        void (*callback)(void);
    };


    void vulnerable(void) {
        struct config cfg;
        cfg.mode = 1;
        cfg.path = "/tmp";
        // flags and callback remain uninitialized
        
        if (cfg.flags & SECURE) {    // UDA - flags is not initialized and therefore contains garbage.
            // ...
        }
        cfg.callback();              // UDA - executes random address
    }
    ```

    This particular example is very simple. What generally happens is that there is a structure initializer function that takes user-controlled data and makes decisions based on it. This can lead to the user poisoning the data that the function takes so that it follows paths that leave certain structure fields uninitialized. Then, in another function, the program uses these uninitialized fields leading to UDA.

    <br>

4. **Uninitialized malloc**.

    The following example is similar to partial initialization of a buffer on the stack but on the heap. A pointer is declared and initialized through the *malloc()* function with an excessively large *size*. Subsequently, part of this memory block is written to, leaving a final part untouched which consequently contains residual data. The partially initialized buffer is then used in another part of the program, leading to a UDA vulnerability.

    ```c
    void vulnerable(size_t size) {
        char *buf = malloc(size);    // memory with residual data
        
        if (some_condition) {
            memcpy(buf, data, len);  // partially initializes (len < size)
        }
        
        process(buf, size);          // may read uninitialized data
    }
    ```

    <br>

5. **Unassigned Out Parameter in Error Path**:

    The following code is a particular example of a function that should initialize a variable; however, due to various issues, it may take a path that leaves the value uninitialized, allowing the program to use a variable containing "garbage":

    ```c
    int get_value(int *out_value) {
        if (error_condition) {
            return -1;               // out_value is not touched
        }
        *out_value = compute();
        return 0;
    }

    void vulnerable(void) {
        int value;                   // not initialized
        
        get_value(&value);           // ignores the return
        
        use(value);                  // UDA if there was an error
    }
    ```

    <br>

6. **Union with Incorrect Member Read**:

    A "union" is a C object consisting of a memory region capable of holding data of different types (int, float, pointer, etc). In this way, this memory region is declared to the compiler as a possible recipient of those data types instead of just one, as would happen with a normal variable declaration that can only hold one data type.

    Note that the following problem can occur: we have a union that holds different data types of different sizes. Initializing one and attempting to access another member of larger size means partially accessing uninitialized data, as in the following case:

    ```c
    union data {
        int as_int;
        float as_float;
        char as_bytes[4];
    };

    void vulnerable(void) {
        union data d;
        d.as_int = 42;
        
        // as_float has a value, but not the "expected" one
        // as_bytes[0-3] are defined, but interpreting as float is UB
        
        float f = d.as_float;        // type punning, possible conceptual UDA
    }
    ```

    A union is defined that can hold an integer (4 bytes) and a float (8 bytes) among others. Assigning an integer and reading a float from the union means reading 4 uninitialized bytes from that memory region.

    <br>

7. **Partially Initialized Array of Pointers/Structs**:

    Another example of a function that partially initializes a memory block by taking parameters potentially controlled or pseudo-controlled by the user.

    ```c
    void vulnerable(int n) {
        void *handlers[10];          // 10 garbage pointers
        
        for (int i = 0; i < n; i++) {
            handlers[i] = get_handler(i);
        }
        
        // if n < 10...
        handlers[9]();               // UDA → executes random address
    }
    ```

    <br>


8. **Struct Padding**:

    Structures leave gaps due to memory alignment requirements. These are bytes that are not assigned to any field of that structure. Improper use can cause these bytes to be read, which essentially contain "garbage", as in the following example:

    ```c
    struct __attribute__((packed)) safe {
        char a;
        int b;
    };

    struct leaked {
        char a;      // 1 byte
                    // 3 bytes of padding (garbage)
        int b;       // 4 bytes
    };

    void vulnerable(void) {
        struct leaked s;
        s.a = 'x';
        s.b = 42;
        
        write(fd, &s, sizeof(s));    // leaks 3 bytes of padding
    }
    ```

9. **Unchecked Array Access**

    Finally, we present an especially important case where a for-loop with a user-controlled exit condition does not correctly check the number of times it accesses a buffer:

    ```c
    void vulnerable(int user_count) {
        int values[10];
        
        // user_count comes from the user, can be > 10
        for (int i = 0; i < user_count; i++) {
            printf("%d\n", values[i]);  // UDA when i >= 10
        }
    }
    ```

    <br>

#### Detection.

- Essentially we seek to track any use made of partially initialized variables or structures. Any use of these entities is considered improper use.

- Arrays or structures deserve special attention because, even if they appear to be correctly initialized, they may carry uninitialized portions of memory.

- Iterative loops that access a buffer or any other structure incrementally, if not properly written or if their exit condition is controlled by the user, may be vulnerable to UDA.