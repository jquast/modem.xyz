"""PETSCII (Commodore 64/128) encoding -- stub.

PETSCII is the character encoding used by Commodore computers (C64, C128,
VIC-20, Plus/4, etc.).  It has two character sets (shifted/unshifted) with
graphical symbols that do not map cleanly to Unicode.

This is a placeholder.  A full implementation would need to handle:
- Unshifted mode (uppercase + graphics)
- Shifted mode (mixed case + graphics)
- Control characters for color, cursor movement, etc.
- Reverse video mode

For now, this module registers the encoding name so that bbslist.txt can
reference it, but encode/decode operations raise NotImplementedError.
"""

import codecs


class Codec(codecs.Codec):

    def encode(self, input, errors='strict'):
        raise NotImplementedError('PETSCII encoding not yet implemented')

    def decode(self, input, errors='strict'):
        raise NotImplementedError('PETSCII decoding not yet implemented')


class IncrementalEncoder(codecs.IncrementalEncoder):
    def encode(self, input, final=False):
        raise NotImplementedError('PETSCII encoding not yet implemented')


class IncrementalDecoder(codecs.IncrementalDecoder):
    def decode(self, input, final=False):
        raise NotImplementedError('PETSCII decoding not yet implemented')


class StreamWriter(Codec, codecs.StreamWriter):
    pass


class StreamReader(Codec, codecs.StreamReader):
    pass


def getregentry():
    return codecs.CodecInfo(
        name='petscii',
        encode=Codec().encode,
        decode=Codec().decode,
        incrementalencoder=IncrementalEncoder,
        incrementaldecoder=IncrementalDecoder,
        streamreader=StreamReader,
        streamwriter=StreamWriter,
    )


def getaliases():
    return ['cbm', 'commodore', 'c64', 'c128']
