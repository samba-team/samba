# Japanese messages for international release of SWAT.
# Copyright (C) 2001 Ryo Kawahara <rkawa@lbe.co.jp>, 2000.
#
#   This program is free software; you can redistribute it and/or modify
#   it under the terms of the GNU General Public License as published by
#   the Free Software Foundation; either version 2 of the License, or
#   (at your option) any later version.
#
#   This program is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#   GNU General Public License for more details.
#
#   You should have received a copy of the GNU General Public License
#   along with this program; if not, write to the Free Software
#   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
#
msgid ""
msgstr ""
"Project-Id-Version: i18n-swatE VERSION\n"
"POT-Creation-Date: 2001-09-20 20:29+0900\n"
"PO-Revision-Date: 2000-04-03 17:55+09:00\n"
"Last-Translator: TAKAHASHI Motonobu <monyo@samba.gr.jp>\n"
"Language-Team: Samba Team <samba-technical@samba.org>\n"
"MIME-Version: 1.0\n"
"Content-Type: text/plain; charset=Shift_JIS\n"
"Content-Transfer-Encoding: \n"

#: web/swat.c:120
#, c-format
msgid "ERROR: Can't open %s\n"
msgstr "%s をオープンできません\n"

#.
#. str = stripspace(parm->label);
#. strlower (str); //monyo
#. d_printf("<tr><td><A HREF=\"/swat/help/smb.conf.5.html#%s\" target=\"docs\">%s</A>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; %s</td><td>",
#. str, _("Help"), parm->label);
#.
#: web/swat.c:211
msgid "Help"
msgstr "説明"

#: web/swat.c:217 web/swat.c:231 web/swat.c:246 web/swat.c:254 web/swat.c:263
#: web/swat.c:272 web/swat.c:278 web/swat.c:284 web/swat.c:297
msgid "Set Default"
msgstr "既定値に戻す"

#: web/swat.c:502
#, c-format
msgid "Logged in as <b>%s</b><p>\n"
msgstr "<b>%s</b>としてログイン<p>\n"

#: web/swat.c:505
msgid "Home"
msgstr "ホーム"

#: web/swat.c:507
msgid "Globals"
msgstr "全体設定"

#: web/swat.c:508
msgid "Shares"
msgstr "共有設定"

#: web/swat.c:509
msgid "Printers"
msgstr "プリンタ設定"

#: web/swat.c:512
msgid "Status"
msgstr "動作状況"

#: web/swat.c:513
msgid "View Config"
msgstr "設定表\示"

#: web/swat.c:515
msgid "Password Management"
msgstr "パスワード管理・ユーザ管理"

#: web/swat.c:539
msgid "Current Config"
msgstr "現在の設定"

#: web/swat.c:543
msgid "Normal View"
msgstr "標準表示"

#: web/swat.c:545
msgid "Full View"
msgstr "完全表示"

#: web/swat.c:561
msgid "Global Variables"
msgstr "全体設定"

#: web/swat.c:575 web/swat.c:671 web/swat.c:1014
msgid "Commit Changes"
msgstr "設定変更"

#: web/swat.c:579 web/swat.c:674 web/swat.c:1016
msgid "Reset Values"
msgstr "リセット"

#: web/swat.c:581 web/swat.c:676 web/swat.c:1018
msgid "Advanced View"
msgstr "詳細表示"

#: web/swat.c:583 web/swat.c:678 web/swat.c:1020
msgid "Basic View"
msgstr "標準表示"

#: web/swat.c:613
msgid "Share Parameters"
msgstr "共有設定"

#: web/swat.c:642
msgid "Choose Share"
msgstr "共有選択"

#: web/swat.c:656
msgid "Delete Share"
msgstr "共有削除"

#: web/swat.c:663
msgid "Create Share"
msgstr "新規共有作成"

#: web/swat.c:708
msgid "password change in demo mode rejected\n"
msgstr "デモ・モードでのパスワード変更はできません\n"

#: web/swat.c:747
msgid " Must specify \"User Name\" \n"
msgstr "「ユーザ名」を入力ください\n"

#: web/swat.c:763
msgid " Must specify \"Old Password\" \n"
msgstr "「旧パスワード」を入力してください\n"

#: web/swat.c:769
msgid " Must specify \"Remote Machine\" \n"
msgstr "「リモート マシン」を入力してください\n"

#: web/swat.c:776
msgid " Must specify \"New, and Re-typed Passwords\" \n"
msgstr "「新パスワード」を入力し、再入力もしてください\n"

#: web/swat.c:782
msgid " Re-typed password didn't match new password\n"
msgstr "新パスワードの再入力が間違っています\n"

#: web/swat.c:812
#, c-format
msgid " The passwd for '%s' has been changed. \n"
msgstr " '%s' のパスワードは変更されました \n"

#: web/swat.c:814
#, c-format
msgid " The passwd for '%s' has NOT been changed. \n"
msgstr " '%s' のパスワードは変更されませんでした \n"

#: web/swat.c:838
msgid "Server Password Management"
msgstr "ローカル マシンのパスワード管理"

#.
#. * Create all the dialog boxes for data collection
#.
#: web/swat.c:847 web/swat.c:894
msgid " User Name : "
msgstr "ユーザ名 : "

#: web/swat.c:850 web/swat.c:896
msgid " Old Password : "
msgstr "旧パスワード : "

#: web/swat.c:853 web/swat.c:898
msgid " New Password : "
msgstr "新パスワード : "

#: web/swat.c:855 web/swat.c:900
msgid " Re-type New Password : "
msgstr "新パスワード再入力 : "

#: web/swat.c:863 web/swat.c:911
msgid "Change Password"
msgstr "パスワード変更"

#: web/swat.c:866
msgid "Add New User"
msgstr "新規ユーザ追加"

#: web/swat.c:868
msgid "Delete User"
msgstr "ユーザを削除する"

#: web/swat.c:870
msgid "Disable User"
msgstr "使用不可にする"

#: web/swat.c:872
msgid "Enable User"
msgstr "使用可能にする"

#: web/swat.c:885
msgid "Client/Server Password Management"
msgstr "リモート マシンのパスワード管理"

#: web/swat.c:902
msgid " Remote Machine : "
msgstr " リモート マシン : "

#: web/swat.c:940
msgid "Printer Parameters"
msgstr "プリンタ設定 [Printer]"

#: web/swat.c:942
msgid "Important Note:"
msgstr "*注:"

#: web/swat.c:943
msgid "Printer names marked with [*] in the Choose Printer drop-down box "
msgstr "名前の先頭に [*] がついたプリンタ"

#: web/swat.c:944
msgid "are autoloaded printers from "
msgstr "は、"

#: web/swat.c:945
msgid "Printcap Name"
msgstr "printcap name パラメータ"

#: web/swat.c:946
msgid "Attempting to delete these printers from SWAT will have no effect.\n"
msgstr "から自動設定されたものですから、削除することはできません。\n"

#: web/swat.c:980
msgid "Choose Printer"
msgstr "プリンタ選択"

#: web/swat.c:999
msgid "Delete Printer"
msgstr "プリンタ削除"

#: web/swat.c:1006
msgid "Create Printer"
msgstr "プリンタ新規作成"

#: web/statuspage.c:40
msgid "DENY_NONE"
msgstr "拒否なし"

#: web/statuspage.c:41
msgid "DENY_ALL   "
msgstr "すべて拒否"

#: web/statuspage.c:42
msgid "DENY_DOS   "
msgstr "DOSを拒否"

#: web/statuspage.c:43
msgid "DENY_READ  "
msgstr "参照を拒否"

#: web/statuspage.c:44
msgid "DENY_WRITE "
msgstr "更新を拒否"

#: web/statuspage.c:50
msgid "RDONLY     "
msgstr "参照のみ"

#: web/statuspage.c:51
msgid "WRONLY     "
msgstr "挿入のみ"

#: web/statuspage.c:52
msgid "RDWR       "
msgstr "更新    "

#: web/statuspage.c:60
msgid "EXCLUSIVE+BATCH "
msgstr "専有+バッチ "

#: web/statuspage.c:62
msgid "EXCLUSIVE       "
msgstr "専有        "

#: web/statuspage.c:64
msgid "BATCH           "
msgstr "バッチ      "

#: web/statuspage.c:66
msgid "LEVEL_II        "
msgstr "レベル_II   "

#: web/statuspage.c:68
msgid "NONE            "
msgstr "なし        "

#: web/statuspage.c:195
msgid "Server Status"
msgstr "サーバー動作状況"

#: web/statuspage.c:200
msgid "Auto Refresh"
msgstr "自動再表示"

#: web/statuspage.c:201 web/statuspage.c:206
msgid "Refresh Interval: "
msgstr "再表示間隔(秒): "

#: web/statuspage.c:205
msgid "Stop Refreshing"
msgstr "自動表示停止"

#: web/statuspage.c:220
msgid "version:"
msgstr "バージョン:"

#: web/statuspage.c:223
msgid "smbd:"
msgstr "ファイル共有デーモン(smbd):"

#: web/statuspage.c:223 web/statuspage.c:235
msgid "running"
msgstr "動作中"

#: web/statuspage.c:223 web/statuspage.c:235
msgid "not running"
msgstr "停止中"

#: web/statuspage.c:226
msgid "Stop smbd"
msgstr "smbd停止"

#: web/statuspage.c:228
msgid "Start smbd"
msgstr "smbd起動"

#: web/statuspage.c:230
msgid "Restart smbd"
msgstr "smbd再起動"

#: web/statuspage.c:235
msgid "nmbd:"
msgstr "ネーム サービス デーモン(nmbd)"

#: web/statuspage.c:238
msgid "Stop nmbd"
msgstr "nmbd停止"

#: web/statuspage.c:240
msgid "Start nmbd"
msgstr "nmbd起動"

#: web/statuspage.c:242
msgid "Restart nmbd"
msgstr "nmbd再起動"

#: web/statuspage.c:249
msgid "Active Connections"
msgstr "接続中クライアント"

#: web/statuspage.c:251 web/statuspage.c:264 web/statuspage.c:272
msgid "PID"
msgstr "プロセスID"

#: web/statuspage.c:251 web/statuspage.c:264
msgid "Client"
msgstr "クライアント"

#: web/statuspage.c:251
msgid "IP address"
msgstr "IPアドレス"

#: web/statuspage.c:251 web/statuspage.c:264 web/statuspage.c:272
msgid "Date"
msgstr "日付"

#: web/statuspage.c:253
msgid "Kill"
msgstr "切断"

#: web/statuspage.c:261
msgid "Active Shares"
msgstr "接続中共有"

#: web/statuspage.c:264
msgid "Share"
msgstr "共有名"

#: web/statuspage.c:264
msgid "User"
msgstr "ユーザ"

#: web/statuspage.c:264
msgid "Group"
msgstr "グループ"

#: web/statuspage.c:270
msgid "Open Files"
msgstr "使用中ファイル"

#: web/statuspage.c:272
msgid "Sharing"
msgstr "排他モード"

#: web/statuspage.c:272
msgid "R/W"
msgstr "参照/更新"

#: web/statuspage.c:272
msgid "Oplock"
msgstr "便宜ロック(Oplock)"

#: web/statuspage.c:272
msgid "File"
msgstr "ファイル名"

#: param/loadparm.c:641
msgid "Base Options"
msgstr "基本オプション"

#: param/loadparm.c:643
#, fuzzy
msgid "dos charset"
msgstr "有効な文字"

#: param/loadparm.c:644
#, fuzzy
msgid "unix charset"
msgstr "有効な文字"

#: param/loadparm.c:645
msgid "display charset"
msgstr ""

#: param/loadparm.c:646
msgid "comment"
msgstr "コメント"

#: param/loadparm.c:647
msgid "path"
msgstr "パス"

#: param/loadparm.c:648
msgid "directory"
msgstr "ディレクトリ"

#: param/loadparm.c:649
msgid "workgroup"
msgstr "ワークグループ"

#: param/loadparm.c:650
msgid "netbios name"
msgstr "netbios 名"

#: param/loadparm.c:651
msgid "netbios aliases"
msgstr "netbios エイリアス"

#: param/loadparm.c:652
msgid "netbios scope"
msgstr "netbios スコープ"

#: param/loadparm.c:653
msgid "server string"
msgstr "サーバ文字列"

#: param/loadparm.c:654
msgid "interfaces"
msgstr "インターフェース"

#: param/loadparm.c:655
msgid "bind interfaces only"
msgstr "このインターフェースのみ使用"

#: param/loadparm.c:657
msgid "Security Options"
msgstr "セキュリティ オプション"

#: param/loadparm.c:659
msgid "security"
msgstr "セキュリティ"

#: param/loadparm.c:660
msgid "encrypt passwords"
msgstr "パスワードを暗号化"

#: param/loadparm.c:661
msgid "update encrypted"
msgstr "暗号化パスワードに更新"

#: param/loadparm.c:662
msgid "allow trusted domains"
msgstr "信頼できるドメインを許可"

#: param/loadparm.c:663
msgid "alternate permissions"
msgstr "代行パーミッション"

#: param/loadparm.c:664
msgid "hosts equiv"
msgstr "同等のホスト"

#: param/loadparm.c:665
msgid "min passwd length"
msgstr "最小パスワード長"

#: param/loadparm.c:666
msgid "min password length"
msgstr "最小パスワード長"

#: param/loadparm.c:667
msgid "map to guest"
msgstr "ゲストにマップ"

#: param/loadparm.c:668
msgid "null passwords"
msgstr "空パスワード"

#: param/loadparm.c:669
#, fuzzy
msgid "obey pam restrictions"
msgstr "先読み"

#: param/loadparm.c:670
msgid "password server"
msgstr "パスワード サーバ"

#: param/loadparm.c:671
msgid "smb passwd file"
msgstr "smb passwd ファイル"

#: param/loadparm.c:672
#, fuzzy
msgid "private dir"
msgstr "プリンタ ドライバ"

#: param/loadparm.c:673
msgid "passdb module path"
msgstr ""

#: param/loadparm.c:674
msgid "root directory"
msgstr "ルート ディレクトリ"

#: param/loadparm.c:675
msgid "root dir"
msgstr "ルート ディレクトリ"

#: param/loadparm.c:676
msgid "root"
msgstr "ルート"

#: param/loadparm.c:678
#, fuzzy
msgid "pam password change"
msgstr "最小パスワード長"

#: param/loadparm.c:679
msgid "passwd program"
msgstr "パスワード プログラム"

#: param/loadparm.c:680
msgid "passwd chat"
msgstr "パスワード チャット"

#: param/loadparm.c:681
msgid "passwd chat debug"
msgstr "パスワード チャット デバッグ"

#: param/loadparm.c:682
msgid "username map"
msgstr "ユーザ名マップ"

#: param/loadparm.c:683
msgid "password level"
msgstr "パスワード レベル"

#: param/loadparm.c:684
msgid "username level"
msgstr "ユーザ名レベル"

#: param/loadparm.c:685
msgid "unix password sync"
msgstr "unix パスワードを同期させる"

#: param/loadparm.c:686
msgid "restrict anonymous"
msgstr "匿名アクセスの制限"

#: param/loadparm.c:687
msgid "lanman auth"
msgstr ""

#: param/loadparm.c:688
msgid "ntlm auth"
msgstr ""

#: param/loadparm.c:689
msgid "plaintext to smbpasswd"
msgstr ""

#: param/loadparm.c:690
msgid "use rhosts"
msgstr "rhosts を使う"

#: param/loadparm.c:692
msgid "username"
msgstr "ユーザ名"

#: param/loadparm.c:693
msgid "user"
msgstr "ユーザ"

#: param/loadparm.c:694
msgid "users"
msgstr "ユーザ"

#: param/loadparm.c:696
msgid "guest account"
msgstr "ゲスト アカウント"

#: param/loadparm.c:697
msgid "invalid users"
msgstr "無効なユーザ"

#: param/loadparm.c:698
msgid "valid users"
msgstr "有効なユーザ"

#: param/loadparm.c:699
msgid "admin users"
msgstr "管理ユーザ"

#: param/loadparm.c:700
msgid "read list"
msgstr "読み取りリスト"

#: param/loadparm.c:701
msgid "write list"
msgstr "書き込みリスト"

#: param/loadparm.c:702
#, fuzzy
msgid "printer admin"
msgstr "プリンタ名"

#: param/loadparm.c:703
msgid "force user"
msgstr "強制するユーザ"

#: param/loadparm.c:704
msgid "force group"
msgstr "強制するグループ"

#: param/loadparm.c:705
msgid "group"
msgstr "グループ"

#: param/loadparm.c:707
msgid "read only"
msgstr "読み取りのみ"

#: param/loadparm.c:708
msgid "write ok"
msgstr "書き込み可"

#: param/loadparm.c:709
msgid "writeable"
msgstr "書き込み可"

#: param/loadparm.c:710
msgid "writable"
msgstr "書き込み可"

#: param/loadparm.c:712
msgid "create mask"
msgstr "作成時にマスク"

#: param/loadparm.c:713
msgid "create mode"
msgstr "作成時のモード"

#: param/loadparm.c:714
msgid "force create mode"
msgstr "強制する作成時のモード"

#: param/loadparm.c:715
msgid "security mask"
msgstr "セキュリティ マスク"

#: param/loadparm.c:716
msgid "force security mode"
msgstr "強制するセキュリティ モード"

#: param/loadparm.c:717
msgid "directory mask"
msgstr "ディレクトリ マスク"

#: param/loadparm.c:718
msgid "directory mode"
msgstr "ディレクトリ モード"

#: param/loadparm.c:719
msgid "force directory mode"
msgstr "強制するディレクトリ モード"

#: param/loadparm.c:720
msgid "directory security mask"
msgstr "ディレクトリのセキュリティ マスク"

#: param/loadparm.c:721
msgid "force directory security mode"
msgstr "強制するディレクトリのセキュリティ モード"

#: param/loadparm.c:722
msgid "inherit permissions"
msgstr "パーミッションを継承"

#: param/loadparm.c:723
msgid "guest only"
msgstr "ゲストのみ"

#: param/loadparm.c:724
msgid "only guest"
msgstr "ゲストのみ"

#: param/loadparm.c:726
msgid "guest ok"
msgstr "ゲスト可"

#: param/loadparm.c:727
msgid "public"
msgstr "パブリック"

#: param/loadparm.c:729
msgid "only user"
msgstr "ユーザのみ"

#: param/loadparm.c:730
msgid "hosts allow"
msgstr "許可するホスト"

#: param/loadparm.c:731
msgid "allow hosts"
msgstr "許可するホスト"

#: param/loadparm.c:732
msgid "hosts deny"
msgstr "拒否するホスト"

#: param/loadparm.c:733
msgid "deny hosts"
msgstr "拒否するホスト"

#: param/loadparm.c:736
msgid "Secure Socket Layer Options"
msgstr "セキュア ソケット レイアー オプション"

#: param/loadparm.c:737
msgid "ssl"
msgstr "ssl"

#: param/loadparm.c:739
msgid "ssl hosts"
msgstr "ssl ホスト"

#: param/loadparm.c:740
msgid "ssl hosts resign"
msgstr "ssl 未使用ホスト"

#: param/loadparm.c:741
msgid "ssl CA certDir"
msgstr "ssl CA 認証ディレクトリ"

#: param/loadparm.c:742
msgid "ssl CA certFile"
msgstr "ssl CA 認証ファイル"

#: param/loadparm.c:743
msgid "ssl server cert"
msgstr "ssl サーバ認証"

#: param/loadparm.c:744
msgid "ssl server key"
msgstr "ssl サーバ鍵"

#: param/loadparm.c:745
msgid "ssl client cert"
msgstr "ssl クライアント認証"

#: param/loadparm.c:746
msgid "ssl client key"
msgstr "ssl クライアント鍵"

#: param/loadparm.c:747
msgid "ssl require clientcert"
msgstr "ssl クライアント認証を要求"

#: param/loadparm.c:748
msgid "ssl require servercert"
msgstr "ssl サーバ認証を要求"

#: param/loadparm.c:749
msgid "ssl ciphers"
msgstr "ssl 暗号"

#: param/loadparm.c:750
msgid "ssl version"
msgstr "ssl バージョン"

#: param/loadparm.c:751
msgid "ssl compatibility"
msgstr "ssl 互換性"

#: param/loadparm.c:754
msgid "Logging Options"
msgstr "ロギング オプション"

#: param/loadparm.c:755
msgid "log level"
msgstr "ログ レベル"

#: param/loadparm.c:756
#, fuzzy
msgid "debuglevel"
msgstr "デバッグレベル"

#: param/loadparm.c:757
msgid "syslog"
msgstr "syslog"

#: param/loadparm.c:758
msgid "syslog only"
msgstr "syslog のみ"

#: param/loadparm.c:759
msgid "log file"
msgstr "ログ ファイル"

#: param/loadparm.c:761
msgid "max log size"
msgstr "最大ログ サイズ"

#: param/loadparm.c:762
msgid "timestamp logs"
msgstr "タイムスタンプ ログ"

#: param/loadparm.c:763
msgid "debug timestamp"
msgstr "デバッグ タイムスタンプ"

#: param/loadparm.c:764
#, fuzzy
msgid "debug hires timestamp"
msgstr "デバッグ タイムスタンプ"

#: param/loadparm.c:765
msgid "debug pid"
msgstr "デバッグ pid"

#: param/loadparm.c:766
msgid "debug uid"
msgstr "デバッグ uid"

#: param/loadparm.c:768
msgid "Protocol Options"
msgstr "プロトコル オプション"

#: param/loadparm.c:770
msgid "protocol"
msgstr "プロトコル"

#: param/loadparm.c:771
msgid "large readwrite"
msgstr ""

#: param/loadparm.c:772
#, fuzzy
msgid "max protocol"
msgstr "プロトコル"

#: param/loadparm.c:773
#, fuzzy
msgid "min protocol"
msgstr "プロトコル"

#: param/loadparm.c:774
msgid "unicode"
msgstr ""

#: param/loadparm.c:775
msgid "read bmpx"
msgstr "bmpx 読み出し"

#: param/loadparm.c:776
msgid "read raw"
msgstr "raw 読み出し"

#: param/loadparm.c:777
msgid "write raw"
msgstr "raw 書き込み"

#: param/loadparm.c:779
msgid "nt smb support"
msgstr "nt smb サポート"

#: param/loadparm.c:780
msgid "nt pipe support"
msgstr "nt pipe サポート"

#: param/loadparm.c:781
msgid "nt acl support"
msgstr "nt acl サポート"

#: param/loadparm.c:782
msgid "announce version"
msgstr "アナウンス バージョン"

#: param/loadparm.c:783
msgid "announce as"
msgstr "アナウンスする種類"

#: param/loadparm.c:784
msgid "max mux"
msgstr "最大 mux"

#: param/loadparm.c:785
msgid "max xmit"
msgstr "最大 xmit"

#: param/loadparm.c:787
msgid "name resolve order"
msgstr "名前解決の順番"

#: param/loadparm.c:788
msgid "max packet"
msgstr "最大パケット"

#: param/loadparm.c:789
msgid "packet size"
msgstr "パケット サイズ"

#: param/loadparm.c:790
msgid "max ttl"
msgstr "最大 ttl"

#: param/loadparm.c:791
msgid "max wins ttl"
msgstr "最大 wins ttl"

#: param/loadparm.c:792
msgid "min wins ttl"
msgstr "最小 wins ttl"

#: param/loadparm.c:793
msgid "time server"
msgstr "タイム サーバ"

#: param/loadparm.c:795
msgid "Tuning Options"
msgstr "チューニング オプション"

#: param/loadparm.c:797
msgid "change notify timeout"
msgstr "更新通知の間隔"

#: param/loadparm.c:798
msgid "deadtime"
msgstr "切断までの時間"

#: param/loadparm.c:799
msgid "getwd cache"
msgstr "getwd キャッシュ"

#: param/loadparm.c:800
msgid "keepalive"
msgstr ""

#: param/loadparm.c:802
msgid "lpq cache time"
msgstr "lpq キャッシュ時間"

#: param/loadparm.c:803
msgid "max smbd processes"
msgstr ""

#: param/loadparm.c:804
msgid "max connections"
msgstr "最大接続数"

#: param/loadparm.c:805
#, fuzzy
msgid "paranoid server security"
msgstr "ユーザ追加スクリプト"

#: param/loadparm.c:806
msgid "max disk size"
msgstr "最大ディスク サイズ"

#: param/loadparm.c:807
msgid "max open files"
msgstr "最大ファイル オープン数"

#: param/loadparm.c:808
msgid "min print space"
msgstr "最小印刷スペース"

#: param/loadparm.c:809
msgid "read size"
msgstr "読み取りサイズ"

#: param/loadparm.c:811
msgid "socket options"
msgstr "ソ\ケット オプション"

#: param/loadparm.c:812
msgid "stat cache size"
msgstr "stat キャッシュ サイズ"

#: param/loadparm.c:813
#, fuzzy
msgid "strict allocate"
msgstr "厳密なロック"

#: param/loadparm.c:814
msgid "strict sync"
msgstr "厳密な sync"

#: param/loadparm.c:815
msgid "sync always"
msgstr "常に sync"

#: param/loadparm.c:816
#, fuzzy
msgid "use mmap"
msgstr "ユーザ名マップ"

#: param/loadparm.c:817
msgid "hostname lookups"
msgstr ""

#: param/loadparm.c:818
msgid "write cache size"
msgstr "書き込みキャッシュ サイズ"

#: param/loadparm.c:820
msgid "Printing Options"
msgstr "印刷オプション"

#: param/loadparm.c:822
#, fuzzy
msgid "total print jobs"
msgstr "プリンタをロード"

#: param/loadparm.c:823
#, fuzzy
msgid "max print jobs"
msgstr "印刷可"

#: param/loadparm.c:824
msgid "load printers"
msgstr "プリンタをロード"

#: param/loadparm.c:825
msgid "printcap name"
msgstr "printcap 名"

#: param/loadparm.c:826
msgid "printcap"
msgstr "printcap"

#: param/loadparm.c:827
msgid "printable"
msgstr "印刷可"

#: param/loadparm.c:828
msgid "print ok"
msgstr "印刷可"

#: param/loadparm.c:829
msgid "postscript"
msgstr "ポストスクリプト"

#: param/loadparm.c:830
msgid "printing"
msgstr "印刷方法"

#: param/loadparm.c:831
msgid "print command"
msgstr "印刷コマンド"

#: param/loadparm.c:832
msgid "disable spoolss"
msgstr ""

#: param/loadparm.c:833
msgid "lpq command"
msgstr "lpq コマンド"

#: param/loadparm.c:834
msgid "lprm command"
msgstr "lprm コマンド"

#: param/loadparm.c:835
msgid "lppause command"
msgstr "lppause コマンド"

#: param/loadparm.c:836
msgid "lpresume command"
msgstr "lpresume コマンド"

#: param/loadparm.c:837
msgid "queuepause command"
msgstr "キュー停止コマンド"

#: param/loadparm.c:838
msgid "queueresume command"
msgstr "キュー再開コマンド"

#: param/loadparm.c:840
#, fuzzy
msgid "enumports command"
msgstr "印刷コマンド"

#: param/loadparm.c:841
#, fuzzy
msgid "addprinter command"
msgstr "印刷コマンド"

#: param/loadparm.c:842
#, fuzzy
msgid "deleteprinter command"
msgstr "印刷コマンド"

#: param/loadparm.c:843
#, fuzzy
msgid "show add printer wizard"
msgstr "プリンタをロード"

#: param/loadparm.c:844
#, fuzzy
msgid "os2 driver map"
msgstr "ホームディレクトリ マップ"

#: param/loadparm.c:846
msgid "printer name"
msgstr "プリンタ名"

#: param/loadparm.c:847
msgid "printer"
msgstr "プリンタ"

#: param/loadparm.c:848
#, fuzzy
msgid "use client driver"
msgstr "ssl クライアント認証"

#: param/loadparm.c:849
msgid "printer driver"
msgstr "プリンタ ドライバ"

#: param/loadparm.c:850
msgid "printer driver file"
msgstr "プリンタ ドライバ ファイル"

#: param/loadparm.c:851
msgid "printer driver location"
msgstr "プリンタ ドライバの場所"

#: param/loadparm.c:853
msgid "Filename Handling"
msgstr "ファイル名の取扱"

#: param/loadparm.c:854
msgid "strip dot"
msgstr "ドットを削る"

#: param/loadparm.c:856
msgid "mangled stack"
msgstr "名前変換用スタック"

#: param/loadparm.c:857
msgid "default case"
msgstr "既定の文字の大小"

#: param/loadparm.c:858
msgid "case sensitive"
msgstr "大/小文字の区別"

#: param/loadparm.c:859
msgid "casesignames"
msgstr "大/小文字の区別"

#: param/loadparm.c:860
msgid "preserve case"
msgstr "文字の大小を保存"

#: param/loadparm.c:861
msgid "short preserve case"
msgstr "短形式で文字の大小を保存"

#: param/loadparm.c:862
msgid "mangle case"
msgstr "大/小文字の変換"

#: param/loadparm.c:863
msgid "mangling char"
msgstr "変換用文字"

#: param/loadparm.c:864
msgid "hide dot files"
msgstr "ドットファイルを隠す"

#: param/loadparm.c:865
msgid "hide unreadable"
msgstr ""

#: param/loadparm.c:866
msgid "delete veto files"
msgstr "拒否ファイルを削除"

#: param/loadparm.c:867
msgid "veto files"
msgstr "拒否ファイル"

#: param/loadparm.c:868
msgid "hide files"
msgstr "隠しファイル"

#: param/loadparm.c:869
msgid "veto oplock files"
msgstr "oplock を禁止するファイル"

#: param/loadparm.c:870
msgid "map system"
msgstr "システム属性にマップ"

#: param/loadparm.c:871
msgid "map hidden"
msgstr "隠し属性にマップ"

#: param/loadparm.c:872
msgid "map archive"
msgstr "アーカイブ属性にマップ"

#: param/loadparm.c:873
msgid "mangled names"
msgstr "変換した名前で表示"

#: param/loadparm.c:874
msgid "mangled map"
msgstr "変換マップ"

#: param/loadparm.c:875
msgid "stat cache"
msgstr "stat キャッシュ"

#: param/loadparm.c:877
msgid "Domain Options"
msgstr "ドメイン オプション"

#: param/loadparm.c:879
msgid "domain admin group"
msgstr "ドメイン管理グループ"

#: param/loadparm.c:880
msgid "domain guest group"
msgstr "ドメイン ゲスト グループ"

#: param/loadparm.c:883
msgid "groupname map"
msgstr "グループ名マップ"

#: param/loadparm.c:886
msgid "machine password timeout"
msgstr "マシン パスワード タイムアウト"

#: param/loadparm.c:888
msgid "Logon Options"
msgstr "ログオン オプション"

#: param/loadparm.c:890
msgid "add user script"
msgstr "ユーザ追加スクリプト"

#: param/loadparm.c:891
msgid "delete user script"
msgstr "ユーザ削除スクリプト"

#: param/loadparm.c:892
#, fuzzy
msgid "add group script"
msgstr "ユーザ追加スクリプト"

#: param/loadparm.c:893
#, fuzzy
msgid "delete group script"
msgstr "ユーザ削除スクリプト"

#: param/loadparm.c:894
#, fuzzy
msgid "add user to group script"
msgstr "ユーザ追加スクリプト"

#: param/loadparm.c:895
#, fuzzy
msgid "delete user from group script"
msgstr "ユーザ削除スクリプト"

#: param/loadparm.c:896
#, fuzzy
msgid "add machine script"
msgstr "ユーザ追加スクリプト"

#: param/loadparm.c:897
#, fuzzy
msgid "shutdown script"
msgstr "ログオン スクリプト"

#: param/loadparm.c:898
#, fuzzy
msgid "abort shutdown script"
msgstr "ログオン スクリプト"

#: param/loadparm.c:900
msgid "logon script"
msgstr "ログオン スクリプト"

#: param/loadparm.c:901
msgid "logon path"
msgstr "ログオン パス"

#: param/loadparm.c:902
msgid "logon drive"
msgstr "ログオン ドライブ"

#: param/loadparm.c:903
msgid "logon home"
msgstr "ログオン ホーム"

#: param/loadparm.c:904
msgid "domain logons"
msgstr "ドメイン ログオン"

#: param/loadparm.c:906
msgid "Browse Options"
msgstr "コンピュータ一覧表示オプション"

#: param/loadparm.c:908
msgid "os level"
msgstr "os レベル"

#: param/loadparm.c:909
msgid "lm announce"
msgstr "lm アナウンス"

#: param/loadparm.c:910
msgid "lm interval"
msgstr "lm 間隔"

#: param/loadparm.c:911
msgid "preferred master"
msgstr "優先するマスタ"

#: param/loadparm.c:912
msgid "prefered master"
msgstr "優先するマスタ"

#: param/loadparm.c:913
msgid "local master"
msgstr "ローカル マスタ"

#: param/loadparm.c:914
msgid "domain master"
msgstr "ドメイン マスタ"

#: param/loadparm.c:915
msgid "browse list"
msgstr "ブラウズ リスト"

#: param/loadparm.c:916
msgid "browseable"
msgstr "ブラウズ可"

#: param/loadparm.c:917
msgid "browsable"
msgstr "ブラウズ可"

#: param/loadparm.c:918
msgid "enhanced browsing"
msgstr ""

#: param/loadparm.c:920
msgid "WINS Options"
msgstr "WINSオプション"

#: param/loadparm.c:921
msgid "dns proxy"
msgstr "dns プロキシ"

#: param/loadparm.c:922
msgid "wins proxy"
msgstr "wins プロキシ"

#: param/loadparm.c:924
msgid "wins server"
msgstr "wins サーバ"

#: param/loadparm.c:925
msgid "wins support"
msgstr "wins サポート"

#: param/loadparm.c:926
msgid "wins hook"
msgstr "wins フック"

#: param/loadparm.c:928
msgid "Locking Options"
msgstr "ロッキング オプション"

#: param/loadparm.c:930
#, fuzzy
msgid "blocking locks"
msgstr "ロック"

#: param/loadparm.c:931
msgid "fake oplocks"
msgstr "偽装 oplock"

#: param/loadparm.c:932
msgid "kernel oplocks"
msgstr "カーネル oplock"

#: param/loadparm.c:933
msgid "locking"
msgstr "ロック"

#: param/loadparm.c:935
msgid "oplocks"
msgstr "便宜的ロック"

#: param/loadparm.c:936
msgid "level2 oplocks"
msgstr "level2 oplocks"

#: param/loadparm.c:937
msgid "oplock break wait time"
msgstr "oplock 中断の待ち時間"

#: param/loadparm.c:938
msgid "oplock contention limit"
msgstr "oplock 競合の限度"

#: param/loadparm.c:939
#, fuzzy
msgid "posix locking"
msgstr "厳密なロック"

#: param/loadparm.c:940
msgid "strict locking"
msgstr "厳密なロック"

#: param/loadparm.c:941
msgid "share modes"
msgstr "共有モード"

#: param/loadparm.c:944
msgid "Ldap Options"
msgstr "Ldap オプション"

#: param/loadparm.c:946
msgid "ldap server"
msgstr "ldap サーバ"

#: param/loadparm.c:947
msgid "ldap port"
msgstr "ldap ポート"

#: param/loadparm.c:948
msgid "ldap suffix"
msgstr "lpad サフィックス"

#: param/loadparm.c:949
msgid "ldap filter"
msgstr "ldap フィルター"

#: param/loadparm.c:950
msgid "ldap root"
msgstr "ldap ルート"

#: param/loadparm.c:951
msgid "ldap root passwd"
msgstr "ldap ルート パスワード"

#: param/loadparm.c:954
msgid "Miscellaneous Options"
msgstr "その他のオプション"

#: param/loadparm.c:955
#, fuzzy
msgid "add share command"
msgstr "dfree コマンド"

#: param/loadparm.c:956
#, fuzzy
msgid "change share command"
msgstr "メッセージ コマンド"

#: param/loadparm.c:957
#, fuzzy
msgid "delete share command"
msgstr "メッセージ コマンド"

#: param/loadparm.c:959
msgid "config file"
msgstr "設定ファイル"

#: param/loadparm.c:960
msgid "preload"
msgstr "プリロード"

#: param/loadparm.c:961
msgid "auto services"
msgstr "自動サービス"

#: param/loadparm.c:962
msgid "lock dir"
msgstr "ロック ディレクトリ"

#: param/loadparm.c:963
msgid "lock directory"
msgstr "ロック ディレクトリ"

#: param/loadparm.c:965
msgid "utmp directory"
msgstr "utmp ディレクトリ"

#: param/loadparm.c:966
#, fuzzy
msgid "wtmp directory"
msgstr "utmp ディレクトリ"

#: param/loadparm.c:967
#, fuzzy
msgid "utmp"
msgstr "utmp ディレクトリ"

#: param/loadparm.c:970
msgid "default service"
msgstr "既定サービス"

#: param/loadparm.c:971
msgid "default"
msgstr "既定"

#: param/loadparm.c:972
msgid "message command"
msgstr "メッセージ コマンド"

#: param/loadparm.c:973
msgid "dfree command"
msgstr "dfree コマンド"

#: param/loadparm.c:974
msgid "remote announce"
msgstr "リモート アナウンス"

#: param/loadparm.c:975
msgid "remote browse sync"
msgstr "リモートのブラウズリストを同期"

#: param/loadparm.c:976
msgid "socket address"
msgstr "ソ\ケット アドレス"

#: param/loadparm.c:977
msgid "homedir map"
msgstr "ホームディレクトリ マップ"

#: param/loadparm.c:978
msgid "time offset"
msgstr "時間オフセット"

#: param/loadparm.c:979
msgid "NIS homedir"
msgstr "NIS ホームディレクトリ"

#: param/loadparm.c:980
msgid "-valid"
msgstr "-valid"

#: param/loadparm.c:982
msgid "copy"
msgstr "コピー"

#: param/loadparm.c:983
msgid "include"
msgstr "インクルード"

#: param/loadparm.c:984
msgid "exec"
msgstr "実行"

#: param/loadparm.c:985
msgid "preexec"
msgstr "接続時に実行"

#: param/loadparm.c:987
#, fuzzy
msgid "preexec close"
msgstr "接続時に実行"

#: param/loadparm.c:988
msgid "postexec"
msgstr "切断時に実行"

#: param/loadparm.c:989
msgid "root preexec"
msgstr "ルートで接続時実行"

#: param/loadparm.c:990
#, fuzzy
msgid "root preexec close"
msgstr "ルートで接続時実行"

#: param/loadparm.c:991
msgid "root postexec"
msgstr "ルートで切断時実行"

#: param/loadparm.c:992
msgid "available"
msgstr "利用可能"

#: param/loadparm.c:993
msgid "volume"
msgstr "ボリューム"

#: param/loadparm.c:994
msgid "fstype"
msgstr "ファイル システム タイプ"

#: param/loadparm.c:995
#, fuzzy
msgid "set directory"
msgstr "ディレクトリ"

#: param/loadparm.c:996
msgid "source environment"
msgstr ""

#: param/loadparm.c:997
msgid "wide links"
msgstr "広くリンク"

#: param/loadparm.c:998
msgid "follow symlinks"
msgstr "symlink 先を参照"

#: param/loadparm.c:999
msgid "dont descend"
msgstr "下に降りないディレクトリ"

#: param/loadparm.c:1000
msgid "magic script"
msgstr "マジック スクリプト"

#: param/loadparm.c:1001
msgid "magic output"
msgstr "マジック 出力"

#: param/loadparm.c:1002
msgid "delete readonly"
msgstr "読み取りのみのファイルを削除"

#: param/loadparm.c:1003
#, fuzzy
msgid "dos filemode"
msgstr "dos のファイル時刻"

#: param/loadparm.c:1004
msgid "dos filetimes"
msgstr "dos のファイル時刻"

#: param/loadparm.c:1005
msgid "dos filetime resolution"
msgstr "dos のファイル時刻の分解能"

#: param/loadparm.c:1007
msgid "fake directory create times"
msgstr "偽のディレクトリ作成時刻"

#: param/loadparm.c:1008
msgid "panic action"
msgstr "パニック アクション"

#: param/loadparm.c:1009
#, fuzzy
msgid "hide local users"
msgstr "ローカル マスタ"

#: param/loadparm.c:1012
msgid "VFS options"
msgstr "VFSオプション"

#: param/loadparm.c:1014
msgid "vfs object"
msgstr ""

#: param/loadparm.c:1015
#, fuzzy
msgid "vfs options"
msgstr "VFSオプション"

#: param/loadparm.c:1018
#, fuzzy
msgid "msdfs root"
msgstr "ldap ルート"

#: param/loadparm.c:1019
#, fuzzy
msgid "host msdfs"
msgstr "拒否するホスト"

#: param/loadparm.c:1021
msgid "Winbind options"
msgstr "Winbindオプション"

#: param/loadparm.c:1023
#, fuzzy
msgid "winbind uid"
msgstr "Winbindオプション"

#: param/loadparm.c:1024
#, fuzzy
msgid "winbind gid"
msgstr "Winbindオプション"

#: param/loadparm.c:1025
msgid "template homedir"
msgstr ""

#: param/loadparm.c:1026
msgid "template shell"
msgstr ""

#: param/loadparm.c:1027
#, fuzzy
msgid "winbind separator"
msgstr "Winbindオプション"

#: param/loadparm.c:1028
#, fuzzy
msgid "winbind cache time"
msgstr "lpq キャッシュ時間"

#: param/loadparm.c:1029
#, fuzzy
msgid "winbind enum users"
msgstr "無効なユーザ"

#: param/loadparm.c:1030
msgid "winbind enum groups"
msgstr ""

#~ msgid "failed to open %s for writing\n"
#~ msgstr "%s を書き込み用にオープンできません\n"

#~ msgid "Can't reload %s\n"
#~ msgstr "%s を再読み込みできません\n"

#~ msgid "Can't setup password database vectors.\n"
#~ msgstr "パスワード・データベースが見つけられません\n"

#~ msgid "You need to have status=yes in your smb config file\n"
#~ msgstr "smb.conf で status=yes を設定してください\n"

#~ msgid "coding system"
#~ msgstr "コーディング システム"

#~ msgid "client code page"
#~ msgstr "クライアント コードページ"

#~ msgid "revalidate"
#~ msgstr "再認証"

#~ msgid "status"
#~ msgstr "ステータス"

#~ msgid "shared mem size"
#~ msgstr "共有メモリ サイズ"

#~ msgid "character set"
#~ msgstr "文字セット"

#~ msgid "domain groups"
#~ msgstr "ドメイン グループ"

#~ msgid "domain admin users"
#~ msgstr "ドメイン管理ユーザ"

#~ msgid "domain guest users"
#~ msgstr "ドメイン ゲスト ユーザ"

#~ msgid "ole locking compatibility"
#~ msgstr "ole ロックの互換性"

#~ msgid "smbrun"
#~ msgstr "smbrun"

#, fuzzy
#~ msgid "wtmp dir"
#~ msgstr "utmp ディレクトリ"

#~ msgid "unix realname"
#~ msgstr "unix の本名"
