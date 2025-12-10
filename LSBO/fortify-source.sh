# FORTIFY_SOURCE is a preprocessor macro in GCC/Clang compilers framework which helps with BO detection at runtime/compiled-time.

gcc -D_FORTIFY_SOURCE=3 -Wall -g -O2 test.c -o test 

# Is worth to note that there is no difference between a runtime detection and a crash regars to detection.
# Compile-time detection issues do not englobe overflows with runtime-defined values, only with hardcoded values or compile-time defined ones


