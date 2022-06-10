# Writeup for yet-another-printf

| Category        | Author         | Points   | Solves (junior) | Difficulty rating |
| -------------   | -------------  | ------   | ------          |  ----- |
| pwn          | lion           | 500      | 1               | Medium |

## Preface

I did not solve this challenge during the ctf. I got quite close but in the end my exploit was not reliable enough.
I do want to showcase this challenge since it is pretty awesome in my opinion.

## Overview

The description of the challenge reads `Check out this new cool formatter I made! So useful!`. We are essentially
provided with an ELF binary and corresponding source code, a python wrapper that executes it and a patch for glibc.
Lets look at all three of them in detail

## The Wrapper

Lets take a top down approach and look at the wrapper first. It is called `run.py` and located in `deploy/`

```python
import subprocess


def run_code(code: bytes) -> bool:
    rv = subprocess.run(["./yap"], input=code, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env={})

    return rv.returncode == 0


def main():
    print("Welcome to the advanced printf testing service!")
    code = input("Please give me your format to test:")[:4096].strip().encode('ASCII')

    n = 5
    for i in range(n):
        if run_code(code):
            print(f"Attempt {i+1}/{n}: SUCCESS")
        else:
            print(f"Attempt {i+1}/{n}: FAILED")
            exit(1)

    print("Congratulations!")
    with open("flag.txt") as fin:
        print(fin.read())


if __name__ == '__main__':
    main()
```

We are allowed to enter an input of maximum 4096 characters. Then, the `run_code` function
is executed 5 times in succession. It runs the target binary with our input while sending
stdout and stderr to /dev/null, *meaning that we do not get output from the binary*. The
function returns true if we exit with a status of 0. Looking back at main, we see that
we have to get the application to exit 5 times with status 0 to print the flag.

## The Binary

Lets first look at the source code of the challenge binary `yap.c` in `build/`

```c
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>

#define INSIZE 0x1000
#define FOO 0xFF0

struct state {
    char code[INSIZE];
    void* reg0;
    void* reg1;
    void* reg2;
};
int main(int argc, char* argv[]) {
    struct state mystate;

    // let's setup some initial values 
    mystate.reg0 = &mystate.reg1;
    mystate.reg1 = &mystate.reg2;
    mystate.reg2 = mystate.code + FOO;

    setvbuf(stdout, NULL, _IONBF, 0);

    fgets(mystate.code, INSIZE, stdin);

    fprintf(stdout, mystate.code);

    exit(1);
}

void success() { exit(0); }

```

The struct type state holds a char array of `0x1000 = 4096` characters and also holds
three pointers. In main, we first initialize such a struct on the stack and then set the
pointers so that reg0 points to reg1 which points to reg2 which points to 
`mystate.code+FOO = mystate.code + 4080`. So reg2 points to the beginning of the 16 last bytes
of our input. We can observe that our input is read into `mystate.code`, there is no overflow here,
since we read exactly 4096 bytes. In the end, `fprintf` is utilized wrongly. The actual argument
usage should be `fprintf(file_descriptor,format,arguments)`. But in this scenario we control
the `format` parameter, so this is a format string attack. printf will just takes arguments
from the stack, as if we had supplied some (which we didn't, so printf will take whatever happens to
be next on the stack). After the `fprintf` call, `exit` is immediately called with a parameter of 1.
There also exists a function `success` which exits with code 0.

Lets look also look at the binary in its compiled form. We can extract the compilation flags from `build/Makefile` :
`CFLAGS=-Wl,-z,relro,-z,now -pie`. These result in

```console
user@lnx:~/cscg/pwn/yet-another-printf/deploy$ file yap 
yap: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=7f83bf152166dc37885c84a3efe33d9348fbcfcf, for GNU/Linux 3.2.0, not stripped
user@lnx:~/cscg/pwn/yet-another-printf/deploy$ checksec yap
[*] '/home/maxi/cscg/pwn/yet-another-printf/deploy/yap'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
user@lnx:~/cscg/pwn/yet-another-printf/deploy$
```

So we deal with 8 byte addresses, libs are loaded dynamically into an randomized address space, while the stack and the
code of the original binary is also randomized. The stack is not executable but there is no stack cookie.

## The Patch

Lets finally look at `build/printf-patch.diff`. This is a patch for the glibc `fprintf` function located in `stdio-common/vfprintf-internal.c`

```diff
diff --git a/stdio-common/vfprintf-internal.c b/stdio-common/vfprintf-internal.c
index 3be92d4b6e..047d6cfa2d 100644
--- a/stdio-common/vfprintf-internal.c
+++ b/stdio-common/vfprintf-internal.c
@@ -905,35 +905,22 @@ static const uint8_t jump_table[] =
       break;								      \
 									      \
     LABEL (form_pointer):						      \
-      /* Generic pointer.  */						      \
+      /* Generic *padding*.  */						      \
       {									      \
 	const void *ptr;						      \
+        char pad_buf[256] = {0};                                    \
+        unsigned char nnn = 0;            \
 	if (fspec == NULL)						      \
 	  ptr = va_arg (ap, void *);					      \
 	else								      \
 	  ptr = args_value[fspec->data_arg].pa_pointer;			      \
 	if (ptr != NULL)						      \
-	  {								      \
-	    /* If the pointer is not NULL, write it as a %#x spec.  */	      \
-	    base = 16;							      \
-	    number.word = (unsigned long int) ptr;			      \
-	    is_negative = 0;						      \
-	    alt = 1;							      \
-	    group = 0;							      \
-	    spec = L_('x');						      \
-	    goto LABEL (number);					      \
-	  }								      \
-	else								      \
-	  {								      \
-	    /* Write "(nil)" for a nil pointer.  */			      \
-	    string = (CHAR_T *) L_("(nil)");				      \
-	    /* Make sure the full string "(nil)" is printed.  */	      \
-	    if (prec < 5)						      \
-	      prec = 5;							      \
-	    /* This is a wide string iff compiling wprintf.  */		      \
-	    is_long = sizeof (CHAR_T) > 1;				      \
-	    goto LABEL (print_string);					      \
-	  }								      \
+        {   \
+            nnn = *(const unsigned char*) ptr;            \
+        }   \
+        memset(pad_buf, 'X', nnn);                                  \
+        string = (CHAR_T*) pad_buf;                                 \
+        goto LABEL (print_string);                                  \
       }									      \
       /* NOTREACHED */							      \
 									      \
@@ -955,27 +942,27 @@ static const uint8_t jump_table[] =
       if (fspec == NULL)						      \
 	{								      \
 	  if (is_longlong)						      \
-	    *(long long int *) va_arg (ap, void *) = done;		      \
+	    **(long long int **) va_arg (ap, void *) = done;		      \
 	  else if (is_long_num)						      \
-	    *(long int *) va_arg (ap, void *) = done;			      \
+	    **(long int **) va_arg (ap, void *) = done;			      \
 	  else if (is_char)						      \
-	    *(char *) va_arg (ap, void *) = done;			      \
+	    **(char **) va_arg (ap, void *) = done;			      \
 	  else if (!is_short)						      \
-	    *(int *) va_arg (ap, void *) = done;			      \
+	    **(int **) va_arg (ap, void *) = done;			      \
 	  else								      \
-	    *(short int *) va_arg (ap, void *) = done;			      \
+	    **(short int **) va_arg (ap, void *) = done;			      \
 	}								      \
       else								      \
 	if (is_longlong)						      \
-	  *(long long int *) args_value[fspec->data_arg].pa_pointer = done;   \
+	  **(long long int **) args_value[fspec->data_arg].pa_pointer = done;   \
 	else if (is_long_num)						      \
-	  *(long int *) args_value[fspec->data_arg].pa_pointer = done;	      \
+	  **(long int **) args_value[fspec->data_arg].pa_pointer = done;	      \
 	else if (is_char)						      \
-	  *(char *) args_value[fspec->data_arg].pa_pointer = done;	      \
+	  **(char **) args_value[fspec->data_arg].pa_pointer = done;	      \
 	else if (!is_short)						      \
-	  *(int *) args_value[fspec->data_arg].pa_pointer = done;	      \
+	  **(int **) args_value[fspec->data_arg].pa_pointer = done;	      \
 	else								      \
-	  *(short int *) args_value[fspec->data_arg].pa_pointer = done;	      \
+	  **(short int **) args_value[fspec->data_arg].pa_pointer = done;      \
       break;								      \
 									      \
     LABEL (form_strerror):						      \
```

We observe two major functionalities patched here. First of all, the patch
alters the behavior of the `%p` modifier, which should print the address held
by a pointer. In this case, the complete functionality is replaced with
ignoring if the value is null pointer, interpreting it as a pointer to
an unsigned char and following it to read its value. Since it interprets
the target value as an unsigned char, we get the value of the last byte
stored at that 8 byte target value, because of little endian encoding where
the last byte comes first in memory. After reading the value, the function
fills a buffer of size 256 chars (just enough to fit all byte values) with
that many `"X"` chars and prints the buffer. So for example consider:

```c
long val = 0x1122334455667788;
long* ptr = &val;

printf("%p",ptr);
```

The program with the patched glibc would output `0x88 = 136` the character `"X"`.

The second functionality patched is concerned with the `%n` formatter, we can deduce that
by looking at the surrounding code of the patched snippet, where we find a comment stating
`"answer the number of chars written"`. One can see that normal pointer expressions are changed
to double pointer ones. Normally, `%n` writes the number of bytes printed so far in the corresponding
printf call to the memory location pointed to by the next argument. In this patched version, we follow
the pointer two times, perfomring two derefs. So
```c
int val = 0x1122334455667788;
int* ptr = &val;
int** ptr1 = &ptr;

printf("123%n",ptr1);
```

would result in `val = 3`.

## Assessing the situation


