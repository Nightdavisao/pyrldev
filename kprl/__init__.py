"""
kprl – Python implementation of RealLive SEEN.TXT archive pack/unpack.

Public API re-exports:

  from kprl.bytecode import FileHeader, is_bytecode, uncompressed_header, read_file_header
  from kprl.rlcmp    import apply_mask, compress, decompress
  from kprl.archive  import (is_archive, read_index, get_subfile,
                              break_archive, add_to_archive,
                              remove_from_archive, build_archive)
  from kprl.disasm   import disassemble_file
"""

from .bytecode import FileHeader, is_bytecode, uncompressed_header, read_file_header
from .rlcmp    import apply_mask, compress, decompress
from .archive  import (
    is_archive,
    read_index,
    get_subfile,
    break_archive,
    add_to_archive,
    remove_from_archive,
    build_archive,
)
from .disasm   import disassemble_file
from .assemble import assemble_file
from .gan      import gan_to_xml, xml_to_gan, gan_to_ganxml, ganxml_to_gan
from .g00      import read_g00, write_g00, is_g00
from .pdt      import read_pdt, write_pdt, is_pdt
from .rct      import read_rct, write_rct, is_rct
from .rc8      import read_rc8, write_rc8, is_rc8

__all__ = [
    "FileHeader",
    "is_bytecode",
    "uncompressed_header",
    "read_file_header",
    "apply_mask",
    "compress",
    "decompress",
    "is_archive",
    "read_index",
    "get_subfile",
    "break_archive",
    "add_to_archive",
    "remove_from_archive",
    "build_archive",
    "disassemble_file",
    "assemble_file",
    "gan_to_xml", "xml_to_gan", "gan_to_ganxml", "ganxml_to_gan",
    "read_g00", "write_g00", "is_g00",
    "read_pdt", "write_pdt", "is_pdt",
    "read_rct", "write_rct", "is_rct",
    "read_rc8", "write_rc8", "is_rc8",
]
