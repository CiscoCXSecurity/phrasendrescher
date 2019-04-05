# phrasen|drescher - A passphrase cracker

## About The Tool

phrasen|drescher (or short p|d) is a modular and multi processing pass 
phrase cracking tool. It comes with a number of plugins and a simple plugin 
API allows easy development of new plugins. The main features of p|d are:

* Modular with the use of plugins
* Multi processing
* Dictionary attack with or without permutations (uppercase, lowercase, 
  l33t, etc.)
* Incremental brute force attack with custom character maps
* Runs on FreeBSD, NetBSD, OpenBSD, MacOS and Linux

## Installation

```
./configure --with-plugins
make
make install
```
Some plugins require additional libraries. Please read src/plugins/README 
for more details.

## The Plugins

p|d cracks key passphrases, password hashes, accounts of remote web 
applications or whatever a plugin was designed for. The actually cracking 
process is provided by plugins. In this release, there are four modules 
included in the package:

  * rsa-dsa:  cracks RSA and DSA key passphrases
  * mssql:  cracks MS SQL 2000/2005 password hashes
  * ssh:    performs account cracking attacks against an SSH 2 service (supports password, keyboard-interactive and publickey)
  * http-raw: a module for simple HTTP form based account brute-forcing

For further information see src/plugins/README.

## Run It!

### Getting Started

Once you compiled and installed p|d, you should give it a try and run it.
The first choice you'll have to make when using p|d is what plugin to use.
p|d plugins are stored in the system library directory which may differ 
from whatever system you're running it on. If you're unsure which directory 
that is, you can run p|d with the -h flag and it will tell you which the
current plugin directory is:

```
$ pd -h
```

You can to specify the explicit path in the environment variable 
`PD_PLUGINS':

```
$ export PD_PLUGINS=/my/plugin/directory
$ pd -h
```

Every plugin will have additional command line options besides the few 
default p|d command line options. Once you chose a plugin, you can get 
further plugin specific information and command line flags:

```
$ pd rsa-dsa
```


### Cracking Modes

p|d offers two cracking modes. The Incremental Mode (which is used by 
default) does pure brute-forcing of pass phrases while in Dictionary Mode, 
phrases are taken from a word list:

#### Incremental Mode:

This mode expects an argument flag -i that specifies the explicit length 
or a range of words to generate. Generating 8 characters long words, for
instance, can be done this way:

```
$ pd rsa-dsa -i 8 -K private-key
```

And to specify a range. E.g. from 8 characters to 12:

```
$ pd rsa-dsa -i 8:12 -K private-key
```

By default, p|d uses all human readable characters to generate the 
phrases and passwords. However, you can specify your own character map 
in an environment variable `PD_CHARMAP'. For example, in order
to only use lower case characters:

```
$ export PD_CHARMAP="abcdefghijklmnopqrstuvwxyz"
$ pd rsa-dsa -i 6:8 -K private-key
```

The character map also implies the order of the characters to be used
in phrases. So, if you want to do the increment in reverse order,
simply do:

```
$ export PD_CHARMAP="zyxwvutsrqponmlkjihgfedcba"
$ pd rsa-dsa -i 6:8 -K private-key
```

This is generally a good idea, if you know what form of a password you 
can expect, because of the nature of the password to crack or maybe even 
because of password policies (E.g. "password has to begin with a 
character").

#### Dictionary Mode:

Using this mode is straight forward:

```
$ pd rsa-dsa -d wordlist -K private-key
```

For Dictionary Mode, there is a rewriting option. Words, taken from a 
file, can be rewritten after certain rules. E.g. converted to upper or 
lower case, append or prepend a number. All this is done with the `-r' 
flag. This is a list of possible rules:

```
A = all characters upper case
F = first character upper case
L = last character upper case
W = first letter of each word to upper case
a = all characters lower case
f = first character lower case
l = last character lower case
w = first letter of each word to lower case
D = prepend digit
d = append digit
e = 1337 characters
x = all rules
```

In order to rewrite all characters in a word to upper case and to
append a digit (0 to 9) at the end:

```
$ pd rsa-dsa -d wordlist -r Ad -K private-key
```

Sometimes, dictionary words and their rewritten equivalent are identical. 
p|d will discard the rewritten word in this case.

### Writing Plugins

There's a detailed plugin writing guide online at 
http://www.leidecker.info/projects/phrasendrescher/pd_plugins.shtml

### Troubleshooting

If you encounter any bugs, not listed in this section, please refer to
nico@leidecker.info.
