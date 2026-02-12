Introduction
============

What is a MUD?
--------------

A **MUD** (`Multi-User Dungeon <https://en.wikipedia.org/wiki/Multi-user_dungeon>`_) is a text-based
multiplayer world accessed over the internet. Players connect to a MUD server and interact entirely
through written text: you read descriptions of rooms, type commands to move and act, and see the
results as text output. There are no graphics -- everything is conveyed through words, sometimes
with color, and sometimes ASCII or `ANSI art <https://en.wikipedia.org/wiki/ANSI_art>`_.

MUDs are the direct ancestors of modern graphical MMORPGs like World of Warcraft and EverQuest. The
first MUD was created in 1978 by `Roy Trubshaw and Richard Bartle
<https://mud.co.uk/richard/mud1.htm>`_ at the University of Essex. Hundreds of MUDs remain active
today, many maintained by volunteer communities large and small that have kept them running for
decades.

Types of Servers
----------------

The term "MUD" is used loosely to describe many kinds of text-based multiplayer servers. They vary
widely in purpose:

- **MUD** (Multi-User Dungeon)

  The original type. Focused on combat, exploration, quests, and character advancement, usually in
  a fantasy or science fiction setting. Common codebase families include `DikuMUD
  <https://en.wikipedia.org/wiki/DikuMUD>`_, `LPMud <https://en.wikipedia.org/wiki/LPMud>`_, and
  `ROM <https://muds.fandom.com/wiki/ROM>`.

- **MUSH** (Multi-User Shared Hallucination)

  Focused on collaborative storytelling and roleplay rather than combat mechanics. Players can
  build rooms and objects using an in-game scripting language. Common codebases include PennMUSH,
  TinyMUSH, and RhostMUSH.

- **MUX** (Multi-User eXperience)

  Similar to MUSHes, based on the TinyMUX codebase. Often used for freeform roleplay games set in
  licensed universes (superhero comics, TV shows, etc.).

- **MOO** (MUD, Object-Oriented)

  A programmable virtual environment where the world is built from objects with attached code.
  `LambdaMOO <https://en.wikipedia.org/wiki/LambdaMOO>`_ is the most well-known example.

- **MUCK** (Multi-User Created Kingdom)

  Social and creative environments where players build areas and write programs in MUF (Multi-User
  Forth). Fuzzball MUCK is the dominant codebase. MUCKs are popular in the furry community.

  .. warning::

     **Adult Content** -- Some of the most popular servers in this census by player count are not
     traditional games at all but sophisticated adult chat rooms. Servers detected as having adult
     content (via MSSP ``ADULT MATERIAL`` or ``MINIMUM AGE`` >= 18) are tagged with ``Adult`` in the
     genre column of the :doc:`server_list`.

- **Talker**

  Someone quickly figured out they could just remove the dungeon from a MUD codebase and have a
  basic "chat server", A text-based chat system with rooms but minimal or no game mechanics.

What is Telnet?
---------------

**Telnet** is a network protocol from 1969 (`RFC 854
<https://datatracker.ietf.org/doc/html/rfc854>`_) that establishes a two-way text connection over
the internet. Despite its age, Telnet remains widely deployed and used all over the world for
embedded systems. Its longevity comes from its simplicity: it is portable, accessible, and easy to
develop for, which is why MUD communities have adopted it for so long.

When you connect to a MUD, your client opens a TCP connection to the server's address and port,
this is the most basic networking connection, the server sends text and for you to read,
and you type commands that are sent back.

Although the Telnet protocol has **option negotiation**, a complex procedure of negotiating extended
options, a majority of the MUD servers surveyed do not perform any Telnet option negotiation at all.
They simply send and receive raw ASCII text, which is fully compliant with the original standard.

One special note, is that many MUD codebases predate general Unicode support and may emit non-ASCII
data for art or language accents, usually in UTF-8 though some older code bases may still use legacy
encodings like CP437 or latin1.

See Also: BBSes
----------------

MUDs are related to **BBSes** (Bulletin Board Systems) -- both use Telnet, but MUDs typically
operate in **line mode** with ASCII or UTF-8, while BBSes use **character-at-a-time** with legacy
encodings like CP437 for ANSI art. A companion BBS census is at `bbs.modem.xyz
<https://bbs.modem.xyz/>`_.

About This Site
---------------

This site acts as a discovery of international MUDs.

This directory is unique in that **fingerprinting** of the telnet options negotiated are captured,
and serves are cataloged by this fingerprint.  It was created by the author of the Python
`telnetlib3 <https://github.com/jquast/telnetlib3>`_ library, and, uses the
``telnetlib3-fingerprint`` client to gather the results shown here.

The list of MUDs scanned is from the github-managed file, `mudlist.txt
<https://github.com/jquast/modem.xyz/blob/master/data-muds/mudlist.txt>`_, you are welcome to add
anything by pull request, or to make any other changes or recommendations to this website.

Better Sites
------------

If you are looking for the most popular MUDs to play with other people, detailed historical and live
data, user reviews and descriptions, these other sites are probably a lot more helpful!

- https://lociterm.com/home/
- https://www.topmudsites.com/
- https://mudstats.com
- https://www.mudverse.com/
- https://telnet.org/

Questions
---------

Exercises for the reader!

- How do MUDs differ from text adventure games and `BBSs <https://bbs.modem.xyz/>`_?
- Why is ASCII so common? Why are colors optional?
- Why do MUDs often suggest using special clients?
- How do MUD clients differ from BBS clients?
- What kind of systems did MUDs run on and why is linemode preferred?
- Why are MUDs popular with the visually impaired?
- MUD clients offer scripting, what kind of tasks could you automate?
- What popular games started with MUD codebases? Any famous game developers?
- Sometimes games require customized clients, why?
