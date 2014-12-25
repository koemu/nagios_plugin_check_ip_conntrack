# check_ip_conntrack - Checking ip_conntrack for Nagios

- Copyright(C) 2014 Yuichiro SAITO (@koemu)

- This software is released under the MIT License, see LICENSE.txt.


## Requirements

- OS: Linux Kernel 2.6.18 or above
- Python: 2.6 or 2.7

## Usage

- --version 本プログラムのバージョンを表示します。
- -h, --help コマンドラインのヘルプを表示します。
- -w \<free\>, --warning=\<free\> 空きが指定した値未満になった場合、Warningステータスを返します。パーセントか、残数を選択して設定できます。
- -c \<free\>, --critical=\<free\> 空きが指定した値未満になった場合、Criticalステータスを返します。パーセントか、残数を選択して設定できます。
- -V, --verbose メッセージを詳細に表示します。デバッグ用です。

## changelog

* 2014-12 0.0.1 Initial release.

