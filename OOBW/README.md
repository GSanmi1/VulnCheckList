### Protocol for Out-Of-Bounds

An Out-Of-Bounds Write is a vulnerability whereby an attacker gains control over a memory location where data is subsequently written, thus enabling data to be written outside the memory region intended for such data.

Sometimes an attacker can exploit this vulnerability further because, in addition to controlling the location being written to, they also control what is being written, escalating the vulnerability into a "what-where write" vulnerability, though this is not always the case.

The key to this vulnerability is that, as a result of user control over a variable of any type in the code, data gets written outside the memory region intended for it, regardless of whether or not that asme data is also controlled by said user. More information on the following [link](https://gsanmi1.github.io/2025-11-26-Out-Of-Bounds-Write/)

<br>

### OOBW Detection and Examples

This vulnerability can take a wide variety of heterogeneous forms. Among the most commonly involved factors are assignments or data-copying syscalls (such as memcpy) within loops whose exit condition is user-controlled, or similar patterns.
Some examples are provided below:

1. CVE-2019-10540

    ```c    
    //user-controlled: Length, OTA_DataPtr
    char GlobalBuffer[10 * 0xB0 + 6];

    unsigned int itemCount = 0;

    for (unsigned int i = 0; i < Length; i += 0x44){
        memcpy(GlobalBuffer + 6 + itemCount * 0xB0, OTA_DataPtr + i, 0x44);
        itemCount++;
    }
    ```
    In the code above, there is a for loop with a user-controlled exit condition (i < Length). 

    Within this loop, *memcpy()* copies data to a memory address expressed as a base pointer plus an offset that grows by one each iteration. 

    Since the loop is user-controlled, it can iterate as many times as desired, and therefore the user also has control over the offset, and consequently partial control over the destination memory address, which can end up pointing outside *GlobalBuffer* variable. In this case, although of lesser importance, the user also controls what gets written to the buffer.

<br>

2. CVE-2020-1020

    Again, a user-controlled for-loop in which the iteration index is used to assign values to a buffer. In this case, the attacker does not control what is being placed into *ptrs*, but the fact that values can be written to *ptrs\[3\]\[i\]* already constitutes an out-of-bounds:

    ```c    
    //user-controlled: g_font->numMasters
    Fixed16_16* ptrs[2];
    Fixed16_16 values[2];
    //...
    for (int num = 0; num < g_font->numMasters; num++) {
        ptrs[num][i] = values[num];
    }
    ```

    Note that, although *values* is a 2-item array, we have:

    ```c
    values[i] = *(values + i * sizeof(Fixed16_16))
    ```

    The compiler accesses the memory address and dereferences it regardless of whether it belongs to the array or not.

<br>

3. CVE-2021-26675

    Another example:

    ```c    
    //user-controlled: field_count, ptr, end
    while (field_count-- > 0 && ptr < end) {
            //...
            uptr += ulen;
            *uptr++ = '\0';

            ptr += pos;

            /*
            * We copy also the fixed portion of the result (type, class,
            * ttl, address length and the address)
            */
            memcpy(uptr, ptr, NS_RRFIXEDSZ); /*KC: NS_RRFIXEDSZ = 10*/

            dns_type = uptr[0] << 8 | uptr[1];
            dns_class = uptr[2] << 8 | uptr[3];

            if (dns_class != ns_c_in)
                goto out;

            ptr += NS_RRFIXEDSZ;
            uptr += NS_RRFIXEDSZ;
        //...
    }
    ```

    A *memcpy()* call copies data to a destination within a while loop whose exit condition is attacker-controlled. In the first iteration nothing unusual occurs — the amount of data written increases based on a macro not defined by the user — but both source and destination pointers increment, so if the loop iterates enough times, an out-of-bounds write will occur.

In any case, detecting an OOBW requires meticulous examination of the code's execution flow, since most of the time these vulnerabilities are not obvious at first glance.