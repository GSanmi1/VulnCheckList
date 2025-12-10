gcc -D_FORTIFY_SOURCE=3 -Wall -g -O2 test.c -o test # Buffer overflow detection at runtime and compile time.

# Is worth to note that there is no difference between a runtime detection and a crash regars to detection.
# Compile-time detection issues do not englobe overflows with runtime-defined values, only with hardcoded values or compile-time defined ones


