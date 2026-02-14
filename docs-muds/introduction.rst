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

.. youtube:: JqC66POqhY4


What is Telnet?
---------------

`Telnet <https://en.wikipedia.org/wiki/Telnet>`_ is one of the earliest network protocols still in
use today. Developed for `ARPANET <https://en.wikipedia.org/wiki/ARPANET>`_ in 1969 and described in
`RFC 97 <https://datatracker.ietf.org/doc/html/rfc97>`_), it allowed systems to establish a two-way
text-only connection over the internet. Despite its age, Telnet remains widely deployed and used all
over the world and for embedded/IoT systems.

Although the Telnet protocol has **option negotiation**, a complex procedure of negotiating extended
options, a majority of the MUD servers surveyed do not perform any Telnet option negotiation at all.
They simply send and receive raw ASCII text, which is fully compliant with the original standard.

See Also: BBSes
~~~~~~~~~~~~~~~

MUDs are related to **BBSes** (Bulletin Board Systems) -- both use Telnet, but MUDs typically
operate in **line mode** with ASCII or UTF-8, while BBSes use **character-at-a-time** with legacy
encodings like CP437 for ANSI art. A companion BBS census is at `bbs.modem.xyz
<https://bbs.modem.xyz/>`_.

Playing MUDs today
------------------

You may "just telnet" to many MUD servers to try them out. However, for serious playing you will
likely want a better client that provides line editing, history control, and command completion not
typically ofered by MUD servers. There are also MUD extensions for all kinds of purposes like
character stats or even audio.

Two popular open source actively developed clients,

- Mudlet https://www.mudlet.org/ - mouse-based interface
- tintin++ https://tintin.mudhalla.net/ - CLI interface

Types of Servers
~~~~~~~~~~~~~~~~

The term "MUD" is used loosely to describe many kinds of text-based multiplayer servers. They vary
widely in purpose:

- **MUD** (Multi-User Dungeon)

  The original type. Focused on combat, exploration, quests, and character advancement, usually in
  a fantasy or science fiction setting. Common codebase families include `DikuMUD
  <https://en.wikipedia.org/wiki/DikuMUD>`_, `LPMud <https://en.wikipedia.org/wiki/LPMud>`_, and
  `ROM <https://muds.fandom.com/wiki/ROM>`_.

- **MUSH** (Multi-User Shared Hallucination)

  Focused on collaborative storytelling and roleplay rather than combat mechanics. Players can
  build rooms and objects using an in-game scripting language. Common codebases include `PennMUSH
  <https://github.com/pennmush/pennmush>`_, `TinyMUSH <https://github.com/TinyMUSH/TinyMUSH>`_, and
  `RhostMUSH <https://github.com/RhostMUSH/trunk>`_.

- **MUX** (Multi-User eXperience)

  Similar to MUSHes, based on the TinyMUX codebase. Often used for freeform roleplay games set in
  licensed universes (superhero comics, TV shows, etc.).

- **MOO** (MUD, Object-Oriented)

  A programmable virtual environment where the world is built from objects with attached code.
  `LambdaMOO <https://en.wikipedia.org/wiki/LambdaMOO>`_ is the most well-known example.

- **MUCK** (Multi-User Created Kingdom)

  Social and creative environments where players build areas and write programs in `MUF
  <https://www.mufarchive.com/>`_ (Multi-User Forth). `Fuzzball MUCK
  <https://github.com/fuzzball-muck/fuzzball>`_ is the dominant codebase. MUCKs
  are popular in the furry community.

  .. warning::

     **Adult Content** -- Some of the most popular servers in this census by player count are not
     traditional games at all but sophisticated adult chat rooms. All servers of this kind clearly
     state whether adult content is allowed or strictly forbidden.

About This Site
---------------

This site is a *census* of Telnet-accessible MUDs.

It provides a fast web interface to

- Browse MUDs,
- Preview login banners,
- and examine their Telnet protocol details

It was created by the author of the Python `telnetlib3 <https://telnetlib3.readthedocs.io/>`_ library, and uses the `telnetlib3-fingerprint
<https://telnetlib3.readthedocs.io/en/latest/guidebook.html#fingerprinting-client>`_ CLI to gather
the results shown here.

This list of MUDs was primarily sourced from `lociterm.com <https://www.lociterm.com/>`_.

The file is hosted on Github and all scanning and documentation is automatic. Suggest a change to
`mudlist.txt <https://github.com/jquast/modem.xyz/blob/master/mudlist.txt>`_ to
add or remove or fix an encoding as a pull request.  Feel free to suggest any other changes
or fixes.

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
- What kind of systems do MUDs run on and why is linemode preferred?
- Why are MUDs popular with the visually impaired?
- MUD clients offer scripting, what kind of tasks could you automate?
- What popular games started with MUD codebases? Any famous game developers?
- Sometimes games require customized clients, why?
- Why are so few MUDs on the IANA_designated port 23?
- How do MUD clients differ from BBS clients?
