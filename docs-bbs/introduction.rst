Introduction
============

What is a BBS?
--------------

A **BBS** (`Bulletin Board System <https://en.wikipedia.org/wiki/Bulletin_board_system>`_) is a
computer system that hosts an online meeting place accessible over a network connection. Users
connect to a BBS using terminal software and interact through text-based menus, message boards, file
libraries, and sometimes online games -- all presented as text, sometimes with color and
`ANSI art <https://en.wikipedia.org/wiki/ANSI_art>`_.

The first BBS, `CBBS <https://en.wikipedia.org/wiki/CBBS>`_, was created in 1978 by Ward Christensen
and Randy Suess in Chicago. During the 1980s and 1990s, tens of thousands of BBSes operated
worldwide, most reachable over dial-up modem connections. BBSes were the primary way people
communicated online before the World Wide Web: they hosted discussion forums, shared files, played
`door games <https://en.wikipedia.org/wiki/BBS_door>`_, and exchanged mail through networks like
`FidoNet <https://en.wikipedia.org/wiki/FidoNet>`_.

Although the Web displaced most dial-up BBSes, hundreds remain active today over Telnet (and some
over SSH or the Web). Modern sysops run BBSes as a hobby, preserving the culture and aesthetics of
the pre-Web internet.

BBS Software
------------

Many BBS software packages exist, each with a different style and feature set. Some of the most
common platforms found on Telnet-accessible BBSes today:

**Synchronet**
    One of the most popular modern BBS packages. Open source, cross-platform, with built-in Telnet
    and SSH support, JavaScript scripting, and FidoNet connectivity.

**Mystic BBS**
    A popular BBS package supporting Telnet, SSH, and NNTP. Known for good ANSI art support and
    active development. Runs on Linux, Windows, macOS, and Raspberry Pi.

**ENiGMA\xc2\xbd**
    A modern BBS platform written in Node.js. Supports multiple protocols and has a focus on ANSI
    art and retro aesthetics with modern underpinnings.

**Talisman**
    A newer BBS package written in Rust, focusing on ANSI art and door game support.

**WWIV**
    Originally created in 1984, WWIV has been open-sourced and continues to run on modern systems.
    It was one of the most widely used BBS packages during the dial-up era.

**Renegade**
    A classic DOS-era BBS package that some sysops still run under emulation or on vintage hardware.

**PCBoard**
    One of the most commercially successful BBS packages of the 1990s, known for its speed and
    professional features.

Character Encodings
-------------------

BBS banners and menus are often displayed using `ANSI art
<https://en.wikipedia.org/wiki/ANSI_art>`_ -- text-mode graphics created with colored characters and
special symbols from legacy character sets.

**CP437** (`Code Page 437 <https://en.wikipedia.org/wiki/Code_page_437>`_)
    The original IBM PC character set. Includes box-drawing characters, block elements, and other
    graphical symbols that form the basis of most ANSI art. This is the dominant encoding for
    Telnet-accessible BBSes and is assumed as the default encoding for all BBSes in this census
    unless otherwise specified.

**PETSCII** (`Commodore <https://en.wikipedia.org/wiki/PETSCII>`_)
    The character encoding used by Commodore 64, C128, and other Commodore computers. PETSCII
    includes unique graphical characters and differs significantly from ASCII. Some BBSes accessible
    via Telnet serve PETSCII content for Commodore terminal emulators.

**Atari ST**
    The character encoding used by Atari ST computers, similar to CP437 but with differences in the
    upper 128 characters including Hebrew letters and additional symbols.

**Amiga (Topaz)**
    The Amiga's default system font, Topaz, includes its own set of graphical characters. Some BBSes
    that originated on the Amiga platform may use this encoding.

What is Telnet?
---------------

**Telnet** is a network protocol from 1969 (`RFC 854
<https://datatracker.ietf.org/doc/html/rfc854>`_) that establishes a two-way text connection over
the internet. Despite its age, Telnet remains widely deployed and used all over the world for
embedded systems. Its longevity comes from its simplicity: it is portable, accessible, and easy to
develop for, which is why BBS communities have adopted it for so long.

When you connect to a BBS, your client opens a TCP connection to the server's address and port
number (for example, ``bbs.example.com`` on port ``23``). The server sends text for you to read, and
you type commands that are sent back.

Although Telnet supports **option negotiation**, a majority of the servers surveyed do not perform
any Telnet option negotiation at all -- they simply send and receive raw text. Many BBS codebases
predate general Unicode support and emit non-ASCII data (such as box-drawing symbols and block
elements) in CP437 encoding.

About This Site
---------------

This site is a census of Telnet-accessible Bulletin Board Systems. It provides a search interface to
browse BBSes, preview their login banners, and examine their Telnet protocol behavior without
connecting to them individually.

It was created by the author of the Python `telnetlib3 <https://github.com/jquast/telnetlib3>`_
library, and uses the ``telnetlib3-fingerprint`` client to gather the results shown here.

The list of BBSes scanned is sourced from the `IPTIA BBS Directory
<https://www.ipingthereforeiam.com/bbs/>`_ relay.cfg, cross-referenced against the MUD list at
`muds.modem.xyz <https://muds.modem.xyz/>`_ to exclude MUD servers. The resulting list is
github-managed at `bbslist.txt
<https://github.com/jquast/bbs.modem.xyz/blob/master/data/bbslist.txt>`_. You are welcome to add
anything by pull request, or to make any other changes or recommendations to this website.

BBS Resources
-------------

If you are looking for more comprehensive BBS directories, historical information, or ANSI art
archives, these other sites are excellent resources:

- https://www.telnetbbsguide.com/
- https://bbs.guide/
- https://www.ipingthereforeiam.com/bbs/
- https://sixteencolors.net/
