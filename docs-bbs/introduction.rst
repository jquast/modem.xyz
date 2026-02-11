Introduction
============

What is a BBS?
--------------

A **BBS** (`Bulletin Board System <https://en.wikipedia.org/wiki/Bulletin_board_system>`_) is a
computer system that hosts an online meeting place accessible over a network connection. Users
connect to a BBS to interact through text-based menus, exchange local messages or through networks,
trade files, and play `door games <https://en.wikipedia.org/wiki/BBS_door>`_ games.

.. hint::

    The first BBS, `CBBS <https://en.wikipedia.org/wiki/CBBS>`_, was created in 1978
    by Ward Christensen and Randy Suess in Chicago.

Please enjoy the BBS Documentary:

.. youtube:: LHAkuMHBDKX-s_jE

See Also: MUDs
~~~~~~~~~~~~~~

BBSs are very related to **MUDs** (Multi-User Dungeons): both primarily use telnet, but many BBSs
operate in **character-at-a-time** mode, while MUDs use **line mode**, their preferred clients and
servers are sometimes incompatible with each other.

A census of MUD Telnet servers is at `muds.modem.xyz <https://muds.modem.xyz/>`_.

BBSing Today
------------

During the 1980s and 1990s, tens of thousands of BBSs operated worldwide over telephone lines using
a modem.  By the late 90's, dial-up internet, graphics, E-mail, FTP, and the web browser rapidly
displaced use of the BBS in homes and workplaces.

Many still remain today and can be reached over telnet.  Hobbyist `Sysops
<https://en.wikipedia.org/wiki/Sysop>`_ continue to run BBSs on retrocomputers, like
16 or 32-bit IBM PC-DOS (CP437_), 8-bit Atari (ATASCII_), 8 and 16-bit Commodore (PETSCII_, Topaz_),
and on modern 64-bit Linux and Windows PC's (UTF-8 [#f1]_).

Many of today's BBSs are interlinked through message networks, such as `fidonet
<https://www.fidonet.org/>`_, `Zer0net <https://jackphla.sh/zer0net/>`_, `ArakNet
<https://www.facebook.com/groups/araknet/>`_, and 'fsxNet <https://fsxnet.nz/>`_, though in
significantly reduced volume than their heyday.

Client Software
~~~~~~~~~~~~~~~

The most popular open source clients with accurate font and color presentation of *Western* BBS
Systems are:

- Icy Term https://github.com/mkrueger/icy_tools
- SyncTERM https://syncterm.bbsdev.net/

Modern Terminals
~~~~~~~~~~~~~~~~

Most any modern terminal emulator that you like will do "ok", especially for ASCII-only systems,
and any telnet client that may be installed or may already be present on your computer is fine.
You might be surprised what strange devices you can telnet from!

.. hint::

   If cursor position seems incorrect, try seting your window dimension to exactly 80x25, required
   for almost all legacy "screen-drawing" systems.

An example of using the telnet::

    telnet 1984.ws

Font correction
~~~~~~~~~~~~~~~

For systems with art, **you should adjust the font** of your terminal to match the target system
to more accurately represent it.

- Download and install matching fonts:

  - IBM-PC `Code Page 437 <https://int10h.org/oldschool-pc-fonts/download/>`_,
    ``AcPlus_IBM_VGA_9x8.ttf``
  - Commodore `Amiga Topaz <https://fontstruct.com/fontstructions/show/675155/amiga_topaz>`_,
    ``amiga-topaz.ttf``.

.. image:: 

  .. image:: /_static/konsole-telnet.png
     :alt: 80x24 ANSI art of a skull with graffiti-stylized writing, "ENiGMA½"

.. important::

   Steller graphics! Something seems off though.. are these colors right ??

Color correction
~~~~~~~~~~~~~~~~

For systems with art, **you should also set colors** of your terminal to match.  Modern terminals
often default to "color palettes" that are so far derived from the IBM VGA, Atari, PETSCII or Amiga
colors used in BBS systems that their artwork becomes distorted and rotten!

You can configure the first 16 colors used to match the original colors somewhere in your Terminal's
settings.  Alternatively, the python `telnetlib3`_ client CLI has a nice trick of converting the
first 16 colors to the 24-bit color values intended by the artist::

   telnetlib3-client manalejandro.com 23

.. image:: 

  .. image:: /_static/konsole-telnetlib3.png
     :alt: 80x24 ANSI art of a skull with graffiti-stylized writing, "ENiGMA½"

Encoding correction
~~~~~~~~~~~~~~~~~~~

For systems that do not support UTF-8, you'll see encoding errors:

  .. image:: /_static/ghostty-cp437-telnet.png
     :alt: This "Main" menu, meant to be stylized art, is presented as a font error marked by ``?``

This encoding issue can be resolved with the Python `telnetlib3`_ CLI, ``telnetlib3-client``
argument ``--encoding``.

Because the BBS Software pictured is advertised as `MajorBBS
<https://en.wikipedia.org/wiki/The_Major_BBS>`_ we can infer it is designed for IBM PC clients, and
``--encoding=cp437`` is used to perform encoding translation::

    telnetlib3-client --encoding=cp437 bbs.ccxbbs.net

.. image:: /_static/ghostty-cp437-telnetlib3.png
   :alt: This "Main" menu is now stylized

.. hint:: although `telnetlib3`_ negotiates encoding using `CHARSET RFC
   2066<https://www.rfc-editor.org/rfc/rfc2066.html>`_, but this telnet standard is not in general
   use by Telnet BBS servers, though it may be found on MUDs..

.. todo--finish telnetlib3

    With the 8-bit Commodore `PETSCII <https://github.com/damianvila/font-bescii/releases>`_
    ``Bescii-Mono.ttf`` or Atari ASCII `ATASCII <https://atari8bit.net/projects/artwork/atari-fonts/>`_
    ``EightBit Atari-Classic.ttf`` fonts installed, `telnetlib3`_ can be used to connect to an 8-bit
    Atari BBS::

        telnetlib3-client --force-binary --encoding=ATASCII area52.tk 5200

    - Or an 8-bit Commodore BBS:

        telnetlib3-client --force-binary --encoding=PETSCII valley64.com 6400

Server Software
~~~~~~~~~~~~~~~

A few BBS software packages continue to be developed, are open source, support UTF-8 [#f1]_, and are
compatible with modern computers:

- Sycnrhonet BBS https://www.synchro.net/
- ENiGMA½ https://enigma-bbs.github.io/

And some continue to be developed for retro computing platforms,

- AmiExpress https://github.com/dmcoles/AmiExpress (Amiga)

BBS Software is made by and for `Sysops <https://en.wikipedia.org/wiki/Sysop>`_.  Some people
continue to write (and rewrite!) their own BBS Software to this day, in private and in small
communities, targeting a specific retro computing platform, art style, or programming language.

What is Telnet?
---------------

**Telnet** is a network protocol from 1969 (`RFC 854
<https://datatracker.ietf.org/doc/html/rfc854>`_) that establishes a two-way text connection over
the internet. Despite its age, Telnet remains widely deployed and used all over the world for
embedded systems. Its longevity comes from its simplicity: it is portable, accessible, and easy to
develop for, which is why BBS communities have adopted it for so long.

About This Site
---------------

This site is a *census* of Telnet-accessible BBSs.

It provides a fast web interface to

- browse BBSs,
- preview their login banners
- examine their Telnet protocol

It was created by the author of the Python telnetlib3_ library, and uses the
``telnetlib3-fingerprint`` client to gather the results shown here.

The list of BBSs scanned is sourced from the `IPTIA BBS Directory
<https://www.ipingthereforeiam.com/bbs/>`_ relay.cfg, cross-referenced against the MUD list at
`muds.modem.xyz <https://muds.modem.xyz/>`_ to exclude MUD servers. The resulting list is
github-managed at `bbslist.txt
<https://github.com/jquast/modem.xyz/blob/master/data-bbs/bbslist.txt>`_. Feel free to suggest
any changes by pull request.

Better Sites
------------

If you are looking for more comprehensive BBS directories, historical information, or
ANSI art, these other sites are excellent resources:

- https://www.ipingthereforeiam.com/bbs/
- https://sixteencolors.net/
- https://www.telnetbbsguide.com/
- https://telnet.org/

.. [#f1] Most western BBSs support only CP437, or UTF-8 by *translation*, limitting the ~154,000
   possible codepoints to only the ~255 representable by CP437. Eastern languges, Narrow, Full-Width
   and Zero-width emojis are very rarely supported by BBSs.

.. _telnetlib3: https://telnetlib3.readthedocs.org/
