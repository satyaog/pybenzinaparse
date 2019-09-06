from fields_lists import BoxHeaderFieldsList, FullBoxHeaderFieldsList
from pybzparse import Parser
from ctypes import c_uint32


MAX_UINT_32 = c_uint32(-1).value


class BoxHeader(BoxHeaderFieldsList):
    def __init__(self, length=0):
        super().__init__(length)

        self._start_pos = None
        self._type_cache = None
        self._box_size_cache = None
        self._header_size_cache = None
        self._content_size_cache = None

    @property
    def start_pos(self):
        return self._start_pos

    @property
    def type(self):
        return self._type_cache

    @type.setter
    def type(self, value):
        if value[:4] == b'uuid':
            self._set_field(self._box_type, value[:4])
            self._set_field(self._user_type, value[4:])
        else:
            self._set_field(self._box_type, value)
            self._drop_field(self._user_type)
        self._refresh_cache(len(bytes(self)))

    @property
    def box_size(self):
        return self._box_size_cache

    @box_size.setter
    def box_size(self, value):
        if value > MAX_UINT_32:
            self._set_field(self._box_size, 1)
            self._set_field(self._box_ext_size, value)
        else:
            self._set_field(self._box_size, value)
            self._drop_field(self._box_ext_size)
        self._refresh_cache(len(bytes(self)))

    @property
    def header_size(self):
        return self._header_size_cache

    @property
    def content_size(self):
        return self._content_size_cache

    def parse(self, bstr):
        self._start_pos = bstr.bytepos
        self.parse_fields(bstr)
        self._refresh_cache(bstr.bytepos - self._start_pos)

    def update_box_size(self, content_size):
        header_size = len(bytes(self))
        # Add the size of the box_size field
        if self._box_size.value is None:
            header_size += 4
        # Add the size of the box_ext_size field
        if self._box_ext_size.value is None and \
           header_size + content_size > MAX_UINT_32:
            header_size += 8

        box_size = header_size + content_size

        if self._box_ext_size.value is not None or box_size > MAX_UINT_32:
            self._set_field(self._box_ext_size, box_size)
        else:
            self._set_field(self._box_size, box_size)

        self._refresh_cache(header_size)

    def refresh_cache(self):
        self._refresh_cache(len(bytes(self)))

    def _refresh_cache(self, header_size):
        self._type_cache = (self._box_type.value + self._user_type.value
                            if self._user_type.value is not None
                            else self._box_type.value)
        self._box_size_cache = (self._box_ext_size.value
                                if self._box_ext_size.value is not None
                                else self._box_size.value)
        self._header_size_cache = header_size
        self._content_size_cache = (self._box_size_cache - header_size
                                    if self._box_size_cache is not None
                                    else None)


class FullBoxHeader(BoxHeader, FullBoxHeaderFieldsList, BoxHeaderFieldsList):
    def __init__(self, length=0):
        super().__init__(length)

    def parse_fields(self, bstr):
        super().parse_fields(bstr)
        self._parse_extend_fields(bstr)

    def extend_header(self, bstr, header):
        self._set_field(self._box_size, header.box_size)
        self._set_field(self._box_type, header.box_type)
        self._set_field(self._box_ext_size, header.box_ext_size)
        self._set_field(self._user_type, header.user_type)

        self._start_pos = header.start_pos
        self._parse_extend_fields(bstr)
        self._refresh_cache(bstr.bytepos - self._start_pos)

    def _parse_extend_fields(self, bstr):
        FullBoxHeaderFieldsList.parse_fields(self, bstr)


# Register header
Parser.register_box_header(BoxHeader)