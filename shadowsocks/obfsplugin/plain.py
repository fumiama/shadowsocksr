#!/usr/bin/env python
#
# Copyright 2015-2015 breakwa11
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

from __future__ import absolute_import, division, print_function, \
    with_statement

import os
import sys
import hashlib
import logging
import typing
from ..obfs import (server_info as ServerInfo)

from shadowsocks.common import ord


def create_obfs(method):
    return plain(method)


obfs_map: typing.Dict[str, tuple] = {
    'plain': (create_obfs,),
    'origin': (create_obfs,),
}


class plain(object):
    def __init__(self, method: str):
        self.method = method
        self.server_info: ServerInfo = None

    def init_data(self) -> bytes:
        return b''

    def get_overhead(self, direction) -> int:  # direction: true for c->s false for s->c
        return 0

    def get_server_info(self) -> ServerInfo:
        return self.server_info

    def set_server_info(self, server_info: ServerInfo):
        self.server_info = server_info

    def client_pre_encrypt(self, buf: bytes) -> bytes:
        return buf

    def client_encode(self, buf: bytes) -> bytes:
        return buf

    def client_decode(self, buf: bytes) -> typing.Tuple[bytes, bool]:
        # (buffer_to_recv, is_need_to_encode_and_send_back)
        return (buf, False)

    def client_post_decrypt(self, buf: bytes) -> bytes:
        return buf

    def server_pre_encrypt(self, buf: bytes) -> bytes:
        return buf

    def server_encode(self, buf: bytes) -> bytes:
        return buf

    def server_decode(self, buf: bytes) -> typing.Tuple[bytes, bool, bool]:
        # (buffer_to_recv, is_need_decrypt, is_need_to_encode_and_send_back)
        return (buf, True, False)

    def server_post_decrypt(self, buf: bytes) -> typing.Tuple[bytes, bool]:
        return (buf, False)

    def client_udp_pre_encrypt(self, buf: bytes) -> bytes:
        return buf

    def client_udp_post_decrypt(self, buf: bytes) -> bytes:
        return buf

    def server_udp_pre_encrypt(self, buf: bytes, uid) -> bytes:
        return buf

    def server_udp_post_decrypt(self, buf: bytes) -> typing.Tuple[bytes, any]:
        return (buf, None)

    def dispose(self):
        pass

    def get_head_size(self, buf: bytes, def_value: int) -> int:
        """
        get size From SOCKS5 head type info

        :param buf: bytes       the header from SOCKS5
        :param def_value: int   if cannot detect type
        :return:  the header really size
        """
        if len(buf) < 2:
            return def_value
        head_type = ord(buf[0]) & 0x7
        if head_type == 1:
            return 7
        if head_type == 4:
            return 19
        if head_type == 3:
            return 4 + ord(buf[1])
        return def_value
