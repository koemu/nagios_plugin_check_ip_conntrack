# -*- coding: utf-8 -*-

# ----------------------------------------------
# test_check_ip_conntrack.py
#
# Copyright(C) 2014 Yuichiro SAITO
# This software is released under the MIT License, see LICENSE.txt.
# ----------------------------------------------

import unittest
from check_ip_conntrack import _IPConntrack


# ----------------------------------------------

class TestSequenceFunctions(unittest.TestCase):

    # ----------------------------------------------

    def setUp(self):
        self.dataUsed = 400
        self.dataNone = None
        self.dataMax = 1000
        pass

    # ----------------------------------------------

    def test_paramCheck_OK_1(self):
        """
        矛盾しないチェック %
        """
        checker = _IPConntrack(self.dataUsed, self.dataMax)
        ret = checker.setWarning("20%")
        self.assertEqual(ret, _IPConntrack.STATE_OK)
        ret = checker.setCritical("10%")
        self.assertEqual(ret, _IPConntrack.STATE_OK)

    # ----------------------------------------------

    def test_paramCheck_OK_2(self):
        """
        矛盾しないチェック value
        """
        checker = _IPConntrack(self.dataUsed, self.dataMax)
        ret = checker.setWarning("48")
        self.assertEqual(ret, _IPConntrack.STATE_OK)
        ret = checker.setCritical("24")
        self.assertEqual(ret, _IPConntrack.STATE_OK)

    # ----------------------------------------------

    def test_paramCheck_Unknown_1(self):
        """
        矛盾チェック %
        """
        checker = _IPConntrack(self.dataUsed, self.dataMax)
        ret = checker.setWarning("10%")
        self.assertEqual(ret, _IPConntrack.STATE_OK)
        ret = checker.setCritical("20%")
        self.assertEqual(ret, _IPConntrack.STATE_UNKNOWN)

    # ----------------------------------------------

    def test_paramCheck_Unknown_2(self):
        """
        矛盾チェック %
        """
        checker = _IPConntrack(self.dataUsed, self.dataMax)
        ret = checker.setCritical("20%")
        self.assertEqual(ret, _IPConntrack.STATE_OK)
        ret = checker.setWarning("10%")
        self.assertEqual(ret, _IPConntrack.STATE_UNKNOWN)

    # ----------------------------------------------

    def test_paramCheck_Unknown_3(self):
        """
        矛盾チェック value
        """
        checker = _IPConntrack(self.dataUsed, self.dataMax)
        ret = checker.setWarning("24")
        self.assertEqual(ret, _IPConntrack.STATE_OK)
        ret = checker.setCritical("48")
        self.assertEqual(ret, _IPConntrack.STATE_UNKNOWN)

    # ----------------------------------------------

    def test_paramCheck_Unknown_4(self):
        """
        矛盾チェック value
        """
        checker = _IPConntrack(self.dataUsed, self.dataMax)
        ret = checker.setCritical("48")
        self.assertEqual(ret, _IPConntrack.STATE_OK)
        ret = checker.setWarning("24")
        self.assertEqual(ret, _IPConntrack.STATE_UNKNOWN)

    # ----------------------------------------------

    def test_paramCheck_Unknown_5(self):
        """
        型不一致チェック
        """
        checker = _IPConntrack(self.dataUsed, self.dataMax)
        ret = checker.setCritical("48")
        self.assertEqual(ret, _IPConntrack.STATE_OK)
        ret = checker.setWarning("10%")
        self.assertEqual(ret, _IPConntrack.STATE_UNKNOWN)

    # ----------------------------------------------

    def test_paramCheck_Unknown_6(self):
        """
        型不一致チェック
        """
        checker = _IPConntrack(self.dataUsed, self.dataMax)
        ret = checker.setCritical("20%")
        self.assertEqual(ret, _IPConntrack.STATE_OK)
        ret = checker.setWarning("24")
        self.assertEqual(ret, _IPConntrack.STATE_UNKNOWN)

    # ----------------------------------------------

    def test_validCheck_OK_1(self):
        """
        バリデーション 正常チェック % あり
        """
        checker = _IPConntrack(self.dataUsed, self.dataMax)
        checker.setCritical("10%")
        checker.setWarning("60%")
        self.assertEqual(checker.checkIPConntrack(), _IPConntrack.STATE_OK)

    # ----------------------------------------------

    def test_validCheck_OK_2(self):
        """
        バリデーション 正常チェック value あり
        """
        checker = _IPConntrack(self.dataUsed, self.dataMax)
        checker.setCritical("100")
        checker.setWarning("200")
        self.assertEqual(checker.checkIPConntrack(), _IPConntrack.STATE_OK)

    # ----------------------------------------------

    def test_validCheck_Warning_1(self):
        """
        バリデーション Warningチェック % あり
        """
        checker = _IPConntrack(self.dataUsed, self.dataMax)
        checker.setCritical("60%")
        checker.setWarning("61%")
        self.assertEqual(checker.checkIPConntrack(), _IPConntrack.STATE_WARNING)

    # ----------------------------------------------

    def test_validCheck_Warning_2(self):
        """
        バリデーション Warningチェック value あり
        """
        checker = _IPConntrack(self.dataUsed, self.dataMax)
        checker.setCritical("600")
        checker.setWarning("601")
        self.assertEqual(checker.checkIPConntrack(), _IPConntrack.STATE_WARNING)

    # ----------------------------------------------

    def test_validCheck_Critical_1(self):
        """
        バリデーション Criticalチェック % あり
        """
        checker = _IPConntrack(self.dataUsed, self.dataMax)
        checker.setCritical("61%")
        checker.setWarning("62%")
        self.assertEqual(checker.checkIPConntrack(), _IPConntrack.STATE_CRITICAL)

    # ----------------------------------------------

    def test_validCheck_Critical_2(self):
        """
        バリデーション Criticalチェック value あり
        """
        checker = _IPConntrack(self.dataUsed, self.dataMax)
        checker.setCritical("601")
        checker.setWarning("602")
        self.assertEqual(checker.checkIPConntrack(), _IPConntrack.STATE_CRITICAL)

    # ----------------------------------------------

    def test_validCheck_WarningOnly_1(self):
        """
        バリデーション Warning Onlyチェック % あり
        """
        checker = _IPConntrack(self.dataUsed, self.dataMax)
        checker.setWarning("61%")
        self.assertEqual(checker.checkIPConntrack(), _IPConntrack.STATE_WARNING)

    # ----------------------------------------------

    def test_validCheck_WarningOnly_2(self):
        """
        バリデーション Warning Onlyチェック value あり
        """
        checker = _IPConntrack(self.dataUsed, self.dataMax)
        checker.setWarning("601")
        self.assertEqual(checker.checkIPConntrack(), _IPConntrack.STATE_WARNING)

    # ----------------------------------------------

    def test_validCheck_CriticalOnly_1(self):
        """
        バリデーション Critical Onlyチェック % あり
        """
        checker = _IPConntrack(self.dataUsed, self.dataMax)
        checker.setCritical("61%")
        self.assertEqual(checker.checkIPConntrack(), _IPConntrack.STATE_CRITICAL)

    # ----------------------------------------------

    def test_validCheck_CriticalOnly_2(self):
        """
        バリデーション Critical Onlyチェック value あり
        """
        checker = _IPConntrack(self.dataUsed, self.dataMax)
        checker.setCritical("601")
        self.assertEqual(checker.checkIPConntrack(), _IPConntrack.STATE_CRITICAL)

    # ----------------------------------------------

    def test_validCheck_Unknown_1(self):
        """
        バリデーション Unknownチェック % なし
        """
        checker = _IPConntrack(self.dataNone, self.dataMax)
        checker.setCritical("10%")
        checker.setWarning("80%")
        self.assertEqual(checker.checkIPConntrack(), _IPConntrack.STATE_UNKNOWN)

    # ----------------------------------------------

    def test_validCheck_Unknown_2(self):
        """
        バリデーション 正常チェック value なし
        """
        checker = _IPConntrack(self.dataNone, self.dataMax)
        checker.setCritical("10")
        checker.setWarning("20")
        self.assertEqual(checker.checkIPConntrack(), _IPConntrack.STATE_UNKNOWN)

    # ----------------------------------------------

# ----------------------------------------------

if __name__ == '__main__':
    unittest.main()

# ----------------------------------------------
