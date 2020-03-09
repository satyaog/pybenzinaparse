""" Benzina MP4 Parser based on https://github.com/use-sparingly/pymp4parse """

import logging

import bitstring as bs

log = logging.getLogger(__name__)
log.setLevel(logging.WARN)


class Parser(object):
    _box_header = None
    _box_full_header = None
    _container_box = None
    _default_box = None
    _box_lookup = {}

    @classmethod
    def register_box(cls, box_cls):
        cls._box_lookup[box_cls.type] = box_cls

    @classmethod
    def register_box_header(cls, box_header_cls):
        cls._box_header = box_header_cls

    @classmethod
    def register_box_full_header(cls, box_header_cls):
        cls._box_full_header = box_header_cls

    @classmethod
    def register_container_box(cls, box_cls):
        cls._container_box = box_cls

    @classmethod
    def register_default_box(cls, box_cls):
        cls._default_box = box_cls

    @classmethod
    def parse(cls, bstr=None, filename=None, bytes_input=None, file_input=None,
              offset_bytes=0, headers_only=False, recursive=True):
        """
        Parse an MP4 file or bytes into boxes

        :param bstr: The bitstring to parse
        :type bstr: bitstring.BitStream, bitstring.ConstBitStream
        :param filename: Filename of an mp4 file
        :type filename: str
        :param bytes_input: Bytes of an mp4 file
        :type bytes_input: bytes
        :param file_input: Filename or file object
        :type file_input: str, file
        :param offset_bytes: Start parsing at offset.
        :type offset_bytes: int
        :param headers_only: Ignore data and return just headers. Useful when data is cut short
        :type: headers_only: boolean
        :param recursive: Recursively load sub-boxes
        :type: recursive: boolean
        :return: BMFF Boxes or Headers
        """

        if filename:
            bstr = bs.ConstBitStream(filename=filename, offset=offset_bytes * 8)
        elif bytes_input:
            bstr = bs.ConstBitStream(bytes=bytes_input, offset=offset_bytes * 8)
        elif file_input:
            bstr = bs.ConstBitStream(auto=file_input, offset=offset_bytes * 8)

        log.debug("Starting parse")
        log.debug("Size is %d bits", bstr.len)

        while bstr.pos < bstr.len:
            log.debug("Byte pos before header: %d relative to (%d)",
                      bstr.bytepos, offset_bytes)
            log.debug("Reading header")
            header = cls.parse_header(bstr)
            log.debug("Header type: %s", header.box_type)
            log.debug("Byte pos after header: %d relative to (%d)",
                      bstr.bytepos, offset_bytes)
            yield cls.parse_box(bstr, header, headers_only=headers_only, recursive=recursive)

    @classmethod
    def parse_header(cls, bstr, recursive=True, default_box_cls=None):
        if default_box_cls is None:
            default_box_cls = cls._default_box

        try:
            header_pos = bstr.bytepos
            header = cls._box_header()
            header.parse(bstr)

            box_cls = cls._box_lookup.get(header.type, default_box_cls)

            if box_cls.get_header_cls() != cls._box_header:
                bstr.bytepos = header_pos
                header = box_cls.get_header_cls()()
                header.parse(bstr)
        except bs.ReadError:
            log.error("Premature end of data while reading box header")
            raise
        return header

    @classmethod
    def parse_box(cls, bstr, header, headers_only=False, recursive=True, default_box_cls=None):
        if default_box_cls is None:
            default_box_cls = cls._default_box

        # Get parser method for header type
        box_cls = cls._box_lookup.get(header.type, default_box_cls)

        try:
            if headers_only:
                # Get parser method for header type
                box_cls = cls._box_lookup.get(header.type, default_box_cls)

                box = box_cls(header)
                skipped_bits = box.skip_fields(bstr)

                recursive = recursive and skipped_bits is not None
            else:
                box = box_cls.parse_box(bstr, header)

            if recursive and isinstance(box, cls._container_box):
                box.parse_boxes(bstr, headers_only, recursive)

            bstr.bytepos = box.header.start_pos + box.header.box_size
        except ValueError:
            log.error("Premature end of data")
            raise
        return box

    @classmethod
    def _is_mp4(cls, parser):
        try:
            _ = next(iter(parser))
            return True
        except ValueError:
            return False

    @classmethod
    def is_mp4_s(cls, bytes_input):
        """
        Is bytes_input the contents of an MP4 file

        :param bytes_input: str/bytes to check.
        :type bytes_input: str/bytes.
        :return:
        """

        parser = cls.parse(bytes_input=bytes_input, headers_only=True)
        return cls._is_mp4(parser)

    @classmethod
    def is_mp4(cls, file_input):
        """
        Checks input if it's an MP4 file

        :param file_input: Filename or file object
        :type file_input: str, file
        :returns:  bool.
        :raises: AttributeError, KeyError
        """

        if hasattr(file_input, "read"):
            parser = cls.parse(file_input=file_input, headers_only=True)
        else:
            parser = cls.parse(filename=file_input, headers_only=True)
        return cls._is_mp4(parser)
