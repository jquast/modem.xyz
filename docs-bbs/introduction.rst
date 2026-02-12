Introduction
============

What is a BBS?
--------------

A **BBS** (`Bulletin Board System <https://en.wikipedia.org/wiki/Bulletin_board_system>`_) is a
computer system that hosts an online meeting place accessible over a network connection. Users
connect to a BBS to interact through text-based menus, exchange messages locally or through networks,
trade files, and play games.  The first BBS, `CBBS <https://en.wikipedia.org/wiki/CBBS>`_, was
created in 1978 by Ward Christensen and Randy Suess in Chicago.

`The BBS Documentary <http://www.bbsdocumentary.com/>`_ by Jason Scott provides a great
introduction:

.. youtube:: Dddbe9OuJLU
   :url_parameters: ?start=12&list=PL7nj3G6Jpv2G6Gp6NvN1kUtQuW8QshBWE

What is Telnet?
---------------

`Telnet <https://en.wikipedia.org/wiki/Telnet>`_ is one of the earliest network protocols still in
use today. Developed for `ARPANET <https://en.wikipedia.org/wiki/ARPANET>`_ in 1969 and described in
`RFC 97 <https://datatracker.ietf.org/doc/html/rfc97>`_), it allowed systems to establish a two-way
text-only connection over the internet. Despite its age, Telnet remains widely deployed and used all
over the world and for embedded/IoT systems. Its longevity comes from its simplicity: it is
portable, accessible, and easy to develop for.

See Also: MUDs
~~~~~~~~~~~~~~

- A companion website of MUD Telnet servers is at `muds.modem.xyz <https://muds.modem.xyz/>`_.

BBSs are closely related to `Multi-User Dungeons
<https://en.wikipedia.org/wiki/Multi-user_dungeon>`_: both primarily use telnet, and are used to
play games and chat, BBSs chiefly operate in **character-at-a-time** mode, while MUDs use **line
mode**.  Their preferred clients and servers are sometimes incompatible with each other.

Popular `BBS door <https://en.wikipedia.org/wiki/BBS_door>`_ games, like `Legend of the Red Dragon
<https://en.wikipedia.org/wiki/Legend_of_the_Red_Dragon>`_, `Usurper <https://www.usurper.info/>`_,
`Trade Wars <https://en.wikipedia.org/wiki/Trade_Wars>`_, `Barren Realms Elite
<https://www.johndaileysoftware.com/products/bbsdoors/barrenrealmselite>`_ have the same Multi-User
dungeon gameplay, but game design differs due to the need to limit or even paywall the amount of
allowed turns and time each day, to keep the telephone line free for other "Callers".

BBSing Today
------------

During the 1980s and 1990s, tens of thousands of BBSs operated worldwide over telephone lines using
a modem.  By the late '90s, dial-up internet, graphics, E-mail, FTP, and the web browser rapidly
displaced use of the BBS in homes and workplaces.

Many still remain today and can be reached over telnet.  Hobbyist `Sysops
<https://en.wikipedia.org/wiki/Sysop>`_ continue to run BBSs on retrocomputers, like 16 or 32-bit
IBM PC-DOS (:ref:`CP437 <cp437>`), 8-bit Atari (:ref:`ATASCII <atascii>`), 8 and 16-bit Commodore (:ref:`PETSCII <petscii>`,
:ref:`Topaz <topaz>`), and on modern 64-bit Linux and Windows PCs (UTF-8 [#f1]_).

BBS Software is made by and for `Sysops <https://en.wikipedia.org/wiki/Sysop>`_.  Some people
continue to write (and rewrite!) their own BBS Software to this day, in private and in small
communities, targeting a specific retro computing platform, art style, or programming language.

Many of today's BBSs are interlinked through message networks, such as `fidonet
<https://www.fidonet.org/>`_, `Zer0net <https://jackphla.sh/zer0net/>`_, `ArakNet
<https://www.facebook.com/groups/araknet/>`_, and `fsxNet <https://fsxnet.nz/>`_, though at
significantly reduced volume compared to their heyday.

Client Software
~~~~~~~~~~~~~~~

The most popular open source clients with accurate font, color, and encoding presentation of
*Western* BBS Systems are:

- `Icy Term <https://github.com/mkrueger/icy_tools>`_
- `SyncTERM <https://syncterm.bbsdev.net/>`_

Modern Terminals
~~~~~~~~~~~~~~~~

Most any modern terminal will work for ASCII-only BBS systems, and any telnet client that may be
installed or may already be present on your computer is fine.  You might be surprised what strange
devices you can telnet from!

.. hint::

   Most BBSs require that you set a window size of 80 ``COLUMNS`` by 25 ``LINES``,
   or corruption of screen draw and cursor position can be expected.

Color correction
----------------

.. figure:: /_static/ghostty-telnet.png
   :width: 600px

   80x24 CP437 ANSI art of a skull with graffiti-stylized writing, "ENiGMA½"

Modern terminals often default to "Solarized" or reversed color palettes with disastrous
results to the artwork and colors chosen for retrocomputers.

**You should set the colors** of your terminal to match something like the
`ANSI escape code colors <https://en.wikipedia.org/wiki/ANSI_escape_code#3-bit_and_4-bit>`_. Even
the default xterm colors differ.  You can configure the first 16 colors used to match these colors
somewhere in your Terminal's settings.  It is also suggested to enable "Bold as bright" when
available.

**Alternatively**, the Python `telnetlib3`_ client CLI performs "color correction" by
transliteration of ANSI color sequences to `24-bit Color Sequences
<https://github.com/termstandard/colors>`_ bypassing the palette issue::

   telnetlib3-client manalejandro.com 23

.. figure:: /_static/ghostty-telnetlib3.png
   :width: 600px

   80x24 ANSI art of a skull and graffiti, color-corrected by telnetlib3-client

Encoding correction
-------------------

For systems that do not support UTF-8 [#f1]_, you'll see encoding errors:

.. figure:: /_static/ghostty-cp437-telnet.png
   :width: 600px

   This "Main Menu" is meant to be stylized art, but contains encoding errors, marked by '�'.

cp437
~~~~~

The BBS Software pictured above advertised itself as `MajorBBS
<https://en.wikipedia.org/wiki/The_Major_BBS>`_; we can infer it is designed for IBM PC-DOS
(:ref:`CP437 <cp437>`) encoding, and can use the Python `telnetlib3`_ CLI ``telnetlib3-client`` argument
``--encoding=cp437`` to correct for it::

    telnetlib3-client --encoding=cp437 bbs.ccxbbs.net

.. figure:: /_static/ghostty-cp437-telnetlib3.png
   :width: 600px

   The Main title and border are now correctly displayed as "block art".

topaz
~~~~~

Another BBS, this time **Amiga**:

.. figure:: /_static/konsole-amiga-telnet.png
   :width: 600px

   This Amiga art also contains encoding errors, marked by ``�``.

The Amiga encoding is `latin1
<https://blog.glyphdrawing.club/amiga-ascii-art/#233-what-is-amiga-ascii-art>`_ and can similarly be
fixed by `telnetlib3`_::

    telnetlib3-client --encoding=latin1 absinthebbs.net 1940

.. figure:: /_static/konsole-amiga-telnetlib3.png
   :width: 600px

   The same Amiga art now corrected by the *encoding* specified.

.. todo

    --finish telnetlib3

    With the 8-bit Commodore `PETSCII <https://github.com/damianvila/font-bescii/releases>`_
    ``Bescii-Mono.ttf`` or Atari ASCII `ATASCII <https://atari8bit.net/projects/artwork/atari-fonts/>`_
    ``EightBit Atari-Classic.ttf`` fonts installed, `telnetlib3`_ can be used to connect to an 8-bit

    atascii
    petscii

    Atari BBS::

        telnetlib3-client --force-binary --encoding=ATASCII area52.tk 5200

    - Or an 8-bit Commodore BBS:

        telnetlib3-client --force-binary --encoding=PETSCII valley64.com 6400

Fonts
-----

Though optional for IBM PC-DOS (:ref:`CP437 <cp437>`), as that artwork is faithfully reproduced,
it is **highly suggested** to use a faithful font for ASCII-based 8-bit Atari (:ref:`ATASCII <atascii>`),
and 8 and 16-bit Commodore (:ref:`PETSCII <petscii>`, :ref:`Topaz <topaz>`) systems. 

  - IBM-PC `Code Page 437 <https://int10h.org/oldschool-pc-fonts/download/>`_,
    ``AcPlus_IBM_VGA_9x8.ttf``
  - Commodore `Amiga Topaz <https://gitlab.com/Screwtapello/topaz-unicode#topaz-unicode>`_,
    ``amiga-topaz.ttf``.
  - 8-bit Commodore `PETSCII <https://github.com/damianvila/font-bescii/releases>`_,
    ``Bescii-Mono.ttf``.
  - Atari ASCII `ATASCII <https://atari8bit.net/projects/artwork/atari-fonts/>`_,
    ``EightBit Atari-Classic.ttf``.

Server Software
~~~~~~~~~~~~~~~

A few BBS software packages continue to be developed, are open source, support UTF-8 [#f1]_, and are
compatible with modern computers:

- Synchronet BBS https://www.synchro.net/

- ENiGMA½ https://enigma-bbs.github.io/

And some continue to be developed for retro computing platforms,

- `AmiExpress <https://github.com/dmcoles/AmiExpress>`_ (Amiga)

About This Site
---------------

This site is a *census* of Telnet-accessible BBSs.

It provides a fast web interface to

- Browse BBSs,
- Preview login banners,
- and examine their Telnet protocol details

It was created by the author of the Python telnetlib3_ library, and uses the `telnetlib3-fingerprint
<https://telnetlib3.readthedocs.io/en/latest/guidebook.html#fingerprinting-client>`_ CLI to gather
the results shown here.

This list of BBSs was primarily sourced from the `IPTIA BBS Directory
<https://www.ipingthereforeiam.com/bbs/>`_ and cross-referenced against the MUD list maintained for
`muds.modem.xyz <https://muds.modem.xyz/>`_.

The file is hosted on Github and all scanning and documentation is automatic. Suggest a change to
`bbslist.txt <https://github.com/jquast/modem.xyz/blob/master/data-bbs/bbslist.txt>`_ to
add or remove or fix an encoding as a pull request.  Feel free to suggest any other changes
or fixes.

Better Sites
------------

If you are looking for more comprehensive BBS directories, historical information, or
ANSI art, these other sites are excellent resources:

- https://www.ipingthereforeiam.com/bbs/
- https://sixteencolors.net/
- https://www.telnetbbsguide.com/
- https://breakintochat.com/wiki/Break_Into_Chat
- https://telnet.org/

.. [#f1] Most western BBSs support only CP437, or UTF-8 by *translation*, limiting the ~154,000
   possible codepoints to only the ~255 representable by CP437. Eastern languages, Narrow, Full-Width
   and Zero-width emojis are very rarely supported by BBSs.

.. _telnetlib3: https://telnetlib3.readthedocs.org/

Questions
---------

Exercises for the reader!

- How do BBSs differ from `MUDs <https://muds.modem.xyz/>`_?
- Why do BBS sign-ups ask for your location, birthdate, phone number, and gender?
- Did you find a BBS with message areas? When was the last message posted?
- Why is artwork so common? What common "themes" do you find in the art styles?
- Why do BBS Servers require special clients?
- Why is IBM PC-DOS (:ref:`CP437 <cp437>`) the most popular encoding behind ASCII?
- Can you find the name of a historical BBSs that is no longer online?
- Can you find a historical BBS that is still online today?
- What kind of systems did BBSs run on? What do they run on now?
