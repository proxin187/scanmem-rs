# scanmem-rs

scanmem-rs is a cli memory scanner for linux.

## Features
- Scanning memory
- read/write memory
- buffered read for performance
- executing process with aslr disabled

## Commands

### Attach
Attach opens the specified pid [See procs](Procs),
loads its maps and makes the program ready to scan memory.

```
Usage: attach [pid]
```

### Detach
Detach closes the fd to memory and empties out
entries and maps.

```
Usage: detach
```

### Scan
Scan will scan the specified range of memory for a value,
the range is specified by its map name [See maps](Maps),
the user must provide a bitsize either 32 or 64[See bitsize](BitSize).

```
Usage: scan [value] [bitsize] [range]
```

### Entries
Entries dumps out all address entries where values
from a search has been found.

```
Usage: entries
```

### Read
Read will read a value from the specified address,
the user must provide a bitsize either 32 or 64[See bitsize](BitSize).

```
Usage: read [addr] [bitsize]
```

### Write
Write will write a value to the specified addres,
the user must provide a bitsize either 32 or 64[See bitsize](BitSize).

```
Usage: write [addr] [value] [bitsize]
```

### Lock
Lock will continuisly write a value to an address
in a seperate thread, locking making it locked.
the user must provide a bitsize either 32 or 64[See bitsize](BitSize).

```
Usage: lock [address] [value] [bitsize]
```

### Unlock
Unlock will stop the seperate thread writing to the specified address.

```
Usage: unlock [address]
```

### PtrMap
PtrMap will map out pointer trails until a dead end in a tree-like structure.

```
Usage: ptrmap [address]
```

### exec-no-aslr
exec-no-aslr will execute the specified program path
with [address space layout randomization](https://en.wikipedia.org/wiki/Address_space_layout_randomization) disabled.
this command is usefull for finding addresses that are going to
be used later for example in game cheating.

```
Usage: exec-no-aslr [program]
```

### Maps
Maps will dump out all the [mapped](https://en.wikipedia.org/wiki/Memory_map) areas of memory with their name
in the attached process.

```
Usage: maps
```

### Procs
Procs will dump out all the running processes and their pid.

```
Usage: procs
```

### Exit
Exit will simply exit

```
Usage: exit
```


