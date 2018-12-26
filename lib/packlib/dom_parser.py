# -*- coding: utf-8 -*-

'''
    LibraryPack for the Kodi Media Center
    Kodi is a registered trademark of the XBMC Foundation.
    We are not connected to or in any other way affiliated with Kodi - DMCA: legal@tvaddons.co

        License summary below, for more details please read license.txt file

        This program is free software: you can redistribute it and/or modify
        it under the terms of the GNU General Public License as published by
        the Free Software Foundation, either version 2 of the License, or
        (at your option) any later version.
        This program is distributed in the hope that it will be useful,
        but WITHOUT ANY WARRANTY; without even the implied warranty of
        MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
        GNU General Public License for more details.
        You should have received a copy of the GNU General Public License
        along with this program.  If not, see <http://www.gnu.org/licenses/>.
'''

from __future__ import absolute_import

import six
import re
from packlib import dom_parser2
iteritems = six.iteritems


def parse_dom(html, name='', attrs=None, ret=False):
    if attrs:
        attrs = dict((key, re.compile(value + ('$' if value else ''))) for key, value in iteritems(attrs))
    results = dom_parser2.parse_dom(html, name, attrs, ret)
    if ret:
        # noinspection PyUnresolvedReferences
        results = [result.attrs[ret.lower()] for result in results]
    else:
        results = [result.content for result in results]
    return results
