# Identifying hashes

```
$1$  : MD5
$2a$ : Blowfish
$2y$ : Blowfish, with correct handling of 8 bit characters
$5$  : SHA256
$6$  : SHA512
```

### Identify Hash with Hashid

```bash
 hashid '$apr1$71850310$gh9m4xcAn3MGxogwX/ztb.’
```

```bash
hashid hashes.txt 
```

### Identifying Hashcat mode with Hashid

```bash
hashid '$DCC2$10240#tom#e4e938d12fe5974dc42a90120bd9c90f' -m
```

# HASHCAT

### Hashcat - Example Hashes

```bash
hashcat --example-hashes | less
```

### Hashcat - Syntax

```bash
hashcat -a 0 -m <hash type> <hash file> <wordlist>
```

# Combination Attack

```bash
hashcat -a 1 --stdout file1 file2
```

### Hashcat Syntax

```bash
hashcat -a 1 -m <hash type> <hash file> <wordlist1> <wordlist2>
```

# MASK ATTACK

| **Placeholder** | **Meaning** |
| --- | --- |
| ?l | lower-case ASCII letters (a-z) |
| ?u | upper-case ASCII letters (A-Z) |
| ?d | digits (0-9) |
| ?h | 0123456789abcdef |
| ?H | 0123456789ABCDEF |
| ?s | special characters («space»!"#$%&'()*+,-./:;<=>?@[]^_`{ |
| ?a | ?l?u?d?s |
| ?b | 0x00 - 0xff |

### Mask Attack Syntax

'ILFREIGHTabcxy2015’

```bash
hashcat -a 3 -m 0 md5_mask_example_hash -1 01 'ILFREIGHT?l?l?l?l?l20?1?d’
```

# HYBRID ATTACK

### Hashcat - Hybrid Attack using Wordlists

`football1$`

```bash
hashcat -a 6 -m 0 hybrid_hash <wordlist> '?d?s’
```

`2015football`

```bash
hashcat -a 7 -m 0 hybrid_hash_prefix -1 01 '20?1?d' <wordlist>
```

# Creating Custom Wordlists

### Crunch Syntax

```bash
crunch <minimum length> <maximum length> <charset> -t <pattern> -o <output file>
```

### Crunch Generate Wordlist

```bash
crunch 4 8 -o wordlist
```

### Crunch Wordlist Using Pattern

`ILFREIGHTYYYYXXXX`

```bash
crunch 17 17 -t ILFREIGHT201%@@@@ -o wordlist
```

### Crunch - Create Word List using Pattern

```bash
crunch 12 12 -t 10031998@@@@ -d 1 -o wordlist
```

The "-d" option is used to specify the amount of repetition
