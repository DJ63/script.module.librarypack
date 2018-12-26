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
import zipfile
from  packlib.log_utils import log


def auto(_in, _out):

    return allNoProgress(_in, _out)


def all(_in, _out, dp=None):

    if dp:
        return allWithProgress(_in, _out, dp)

    return allNoProgress(_in, _out)
        

def allNoProgress(_in, _out):

    try:

        zin = zipfile.ZipFile(_in, 'r')
        zin.extractall(_out)
    
    except Exception as e:

        log(str(e))
        return False

    return True


def allWithProgress(_in, _out, dp):

    zin = zipfile.ZipFile(_in,  'r')
    nFiles = float(len(zin.infolist()))
    count = 0

    try:
        for item in zin.infolist():
            count += 1
            update = count / nFiles * 100
            dp.update(int(update),'','',str(item.filename))
            try:
                zin.extract(item, _out)
            except Exception as e:
                log(str(e))

    except Exception as e:
        log(str(e))
        return False

    return True