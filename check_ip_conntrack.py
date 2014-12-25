#!/usr/bin/env python
# -*- coding: utf-8 -*-

# ----------------------------------------------
# check_ip_conntrack
#
# Copyright(C) 2014 Yuichiro SAITO
# This software is released under the MIT License, see LICENSE.txt.
# ----------------------------------------------

import sys
import os
import re
import commands
import logging
import logging.config
from optparse import OptionParser

# ----------------------------------------------
# Global Variables
# ----------------------------------------------
LOG_FORMAT = '%(levelname)s\t%(asctime)s\t%(name)s\t%(funcName)s\t"%(message)s"'
PROGRAM_VERSION = "0.0.1"


# ----------------------------------------------
# Internal Class: _IPConntrack
# ----------------------------------------------
class _IPConntrack:

    STATE_OK = 0
    STATE_WARNING = 1
    STATE_CRITICAL = 2
    STATE_UNKNOWN = 3
    STATE_DEPENDENT = 4
    MODE_UNKNOWN = 0
    MODE_INTEGER = 1
    MODE_PERCENT = 2

    # ----------------------------------------------

    def __init__(self, count=-1, max=-1):
        """
        Constractor
        """
        self.log = logging.getLogger(self.__class__.__name__)

        self.log.debug("START")

        if count is not None and count < 0:
            self.log.debug("START")
            count = self._getIPConntrackCount()
        self.ip_conntrack_count = count

        if max is not None and max < 0:
            max = self._getIPConntrackMax()
        self.ip_conntrack_max = max

        self.warning_mode = self.MODE_UNKNOWN
        self.warning = 0
        self.critical_mode = self.MODE_UNKNOWN
        self.critical = 0

        self.log.debug("END")

    # ----------------------------------------------

    def __del__(self):
        """
        Destructor
        """
        self.log.debug("START")
        pass
        self.log.debug("END")

    # ----------------------------------------------

    def _printWarning(self, msg):

        print "WARNING: %s" % msg

        return self.STATE_WARNING

    # ----------------------------------------------

    def _printCritical(self, msg):

        print "CRITICAL: %s" % msg

        return self.STATE_CRITICAL

    # ----------------------------------------------

    def _printUnknown(self, msg):

        print "UNKNOWN: %s" % msg

        return self.STATE_UNKNOWN

    # ----------------------------------------------

    def _getValueFromCmd(self, cmd):

        self.log.debug("START")

        stdout = commands.getoutput(cmd)
        value = None
        try:
            value = int(stdout)
        except ValueError:
            value = None

        self.log.debug("END")

        return value

    # ----------------------------------------------

    def _getIPConntrackCount(self):

        self.log.debug("START")

        path = None

        if os.path.exists("/proc/sys/net/netfilter/nf_conntrack_count"):
            path = "/proc/sys/net/netfilter/nf_conntrack_count"
        elif os.path.exists("/proc/sys/net/ipv4/netfilter/ip_conntrack_count"):
            path = "/proc/sys/net/ipv4/netfilter/ip_conntrack_count"
        else:
            return None

        cmd = "cat %s" % path
        val = self._getValueFromCmd(cmd)

        self.log.debug("END")

        return val

    # ----------------------------------------------

    def _getIPConntrackMax(self):

        self.log.debug("START")

        path = None

        if os.path.exists("/proc/sys/net/netfilter/nf_conntrack_max"):
            path = "/proc/sys/net/netfilter/nf_conntrack_max"
        elif os.path.exists("/proc/sys/net/ipv4/netfilter/ip_conntrack_max"):
            path = "/proc/sys/net/ipv4/netfilter/ip_conntrack_max"
        else:
            return None

        cmd = "cat %s" % path
        val = self._getValueFromCmd(cmd)

        self.log.debug("END")

        return val

    # ----------------------------------------------

    def _setValue(self, value):
        """
        評価の値を設定します。%がついていればパーセンテージ、なければKiBが評価モードとなります。
        @param value セットしたい値を入れます
        @return dictでセットした値を返します。valueが値, modeが評価のモードです
        """
        self.log.debug("START")

        set_value = {"value": None, "mode": self.MODE_UNKNOWN}

        if re.match("(.*)%$", value):
            set_value["mode"] = self.MODE_PERCENT
            set_value["value"] = int(value.replace("%", ""))
        else:
            set_value["mode"] = self.MODE_INTEGER
            set_value["value"] = int(value)

        self.log.debug(set_value)
        self.log.debug("END")

        return set_value

    # ----------------------------------------------

    def _isValidThreshold(self):
        """
        閾値の関係に異常が無いかを評価します
        @return ステータスを返します
        """
        self.log.debug("START")

        if self.warning_mode == self.MODE_UNKNOWN or self.critical_mode == self.MODE_UNKNOWN:
            # まだ値が設定されていないので評価しない
            pass
        elif self.warning_mode != self.critical_mode:
            # 単位の関係が一緒でない時は評価できないんでエラー
            return self._printUnknown("Mismatch threshold unit.")
        elif self.warning_mode == self.MODE_PERCENT and self.warning > 100:
            return self._printUnknown("Warning is over 100%.")
        elif self.critical_mode == self.MODE_PERCENT and self.critical > 100:
            return self._printUnknown("Critical is over 100%.")
        elif self.warning < self.critical:
            return self._printUnknown("Warning value should be more than critical value.")

        self.log.debug("END")

        return self.STATE_OK

    # ----------------------------------------------

    def setWarning(self, warning):
        """
        warning値をセットします
        @param warning warning値をセットします
        """
        self.log.debug("START")

        set_value = self._setValue(warning)
        self.warning_mode = set_value["mode"]
        self.warning = set_value["value"]

        ret = self._isValidThreshold()
        if ret != self.STATE_OK:
            self.log.debug("EXIT")
            return ret

        self.log.debug("END")

        return self.STATE_OK

    # ----------------------------------------------

    def setCritical(self, critical):
        """
        critical値をセットします
        @param critical critical値をセットします
        """
        self.log.debug("START")

        set_value = self._setValue(critical)
        self.critical_mode = set_value["mode"]
        self.critical = set_value["value"]

        ret = self._isValidThreshold()
        if ret != self.STATE_OK:
            self.log.debug("EXIT")
            return ret

        self.log.debug("END")

        return self.STATE_OK

    # ----------------------------------------------

    def checkIPConntrack(self):
        """
        閾値を評価します
        @return Nagiosの規則に沿った結果を返します
        """
        self.log.debug("START")

        if self.ip_conntrack_count is None or self.ip_conntrack_max is None:
            return self._printUnknown("Unable to get ip_conntrack. Please start up iptables.")

        free = self.ip_conntrack_max - self.ip_conntrack_count
        free_percent = (100.0 * free) / self.ip_conntrack_max

        # 割合で評価
        if self.critical_mode == self.MODE_PERCENT and self.critical > free_percent:
            return self._printCritical("ip_conntrack is drying up (%.1f%%)." % free_percent)
        elif self.warning_mode == self.MODE_PERCENT and self.warning > free_percent:
            return self._printWarning("ip_conntrack is not enough (%.1f%%)." % free_percent)
        # 値で評価
        if self.critical_mode == self.MODE_INTEGER and self.critical > free:
            return self._printCritical("ip_conntrack is drying up (%d KiB)." % free)
        elif self.warning_mode == self.MODE_INTEGER and self.warning > free:
            return self._printWarning("ip_conntrack is not enough (%d KiB)." % free)

        print "OK: Remained ip_conntrack is %d (%.1f%%)." % (free, free_percent)

        self.log.debug("END")

        return self.STATE_OK


# -----------------------------------------------
# Main
# -----------------------------------------------

def main():
    """
    Main
    """

    usage = "Usage: %prog [option ...]"
    version = "%%prog %s\nCopyright (C) 2014 Yuichiro SAITO." % (
        PROGRAM_VERSION)
    parser = OptionParser(usage=usage, version=version)
    parser.add_option("-w", "--warning",
                      type="string",
                      dest="warning",
                      metavar="<free>",
                      help="Exit with WARNING status if less than value of space is free. You can choice count (integer) or percent (%).")
    parser.add_option("-c", "--critical",
                      type="string",
                      dest="critical",
                      metavar="<free>",
                      help="Exit with CRITICAL status if less than value of space is free. You can choice count (integer) or percent (%).")
    parser.add_option("-V", "--verbose",
                      action="store_true",
                      dest="verbose",
                      default=False,
                      help="Verbose mode. (For debug only)")
    (options, args) = parser.parse_args()

    if len(sys.argv) < 4:
        OptionParser.print_version(parser)
        return _IPConntrack.STATE_UNKNOWN

    if options.verbose:
        logging.basicConfig(level=logging.DEBUG, format=LOG_FORMAT)
    else:
        logging.basicConfig(level=logging.WARNING, format=LOG_FORMAT)

    logging.debug("START")

    checker = _IPConntrack()
    ret = checker.setWarning(options.warning)
    if ret != _IPConntrack.STATE_OK:
        logging.debug("EXIT")
        return ret
    ret = checker.setCritical(options.critical)
    if ret != _IPConntrack.STATE_OK:
        logging.debug("EXIT")
        return ret
    ret = checker.checkIPConntrack()
    if ret != _IPConntrack.STATE_OK:
        logging.debug("EXIT")
        return ret

    logging.debug("END")

# ----------------------------------------------

if __name__ == '__main__':
    sys.exit(main())
