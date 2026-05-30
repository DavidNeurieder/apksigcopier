# encoding: utf-8
# SPDX-FileCopyrightText: 2023 FC (Fay) Stegerman <flx@obfusk.net>
# SPDX-License-Identifier: GPL-3.0-or-later

import dataclasses
from dataclasses import dataclass


@dataclass(frozen=True)
class Config:
    exclude_all_meta: bool = False
    copy_extra_bytes: bool = False
    skip_realignment: bool = False

    def replace(self, **kwargs):
        return dataclasses.replace(self, **kwargs)
