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

What is Telnet?
---------------

**Telnet** is a network protocol from 1969 (`RFC 854
<https://datatracker.ietf.org/doc/html/rfc854>`_) that establishes a two-way text connection over
the internet. Despite its age, Telnet remains widely deployed and used all over the world for
embedded systems. Its longevity comes from its simplicity: it is portable, accessible, and easy to
develop for, which is why BBS communities have adopted it for so long.

BBS Server Software
-------------------

Many BBS software packages persist in their historical form, but some software continues to be
updated and can run modern platforms (Linux, Windows, and Mac) and architectures (x86-64/arm64):

- https://www.synchro.net/
- https://mysticbbs.com/
- https://enigma-bbs.github.io/

BBS Client Software
-------------------

The most popular BBS Telnet clients are:

- Icy Term https://github.com/mkrueger/icy_tools
- SyncTERM https://syncterm.bbsdev.net/

As BBS's are telnet-accessible, you would think you could just telnet to it, and you can, but you
will find corrupted screen draws and characters on most bbs's that feature non-ascii artwork. And
that is why these special emulators are suggested as they negotiate about these legacy codepages.

The python ``telnetlib3-client`` CLI can translate CP437, allowing use of telnet with your preferred
terminal emulator instead of any of these special emulators::

    telnetlib3-client --force-binary --encoding=cp437 

See Also: MUDs
--------------

BBSes are related to **MUDs** (Multi-User Dungeons) -- both use Telnet, but BBSes typically operate
**character-at-a-time** with legacy encodings like CP437, while MUDs use **line mode** with ASCII or
UTF-8. A companion MUD census is at `muds.modem.xyz <https://muds.modem.xyz/>`_.

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
<https://github.com/jquast/modem.xyz/blob/master/data/bbslist.txt>`_. Feel free to suggest
any changes by pull request.

BBS Resources
-------------

If you are looking for more comprehensive BBS directories, historical information, or ANSI art
archives, these other sites are excellent resources:

- https://www.ipingthereforeiam.com/bbs/
- https://sixteencolors.net/
- https://www.telnetbbsguide.com/
