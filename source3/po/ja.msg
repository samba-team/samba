# Japanese messages for international release of SWAT.
# Copyright (C) 2003 TAKAHASHI Motonobu <monyo@samba.org>
# Copyright (C) 2000 Ryo Kawahara <rkawa@lbe.co.jp>
#
#   This program is free software; you can redistribute it and/or modify
#   it under the terms of the GNU General Public License as published by
#   the Free Software Foundation; either version 3 of the License, or
#   (at your option) any later version.
#
#   This program is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#   GNU General Public License for more details.
#
#   You should have received a copy of the GNU General Public License
#   along with this program; if not, see <http://www.gnu.org/licenses/>.
#
msgid ""
msgstr ""
"Project-Id-Version: i18n-swat\n"
"Report-Msgid-Bugs-To: \n"
"POT-Creation-Date: 2009-07-29 23:26+0200\n"
"PO-Revision-Date: 2003-09-23 04:38+900\n"
"Last-Translator: TAKAHASHI Motonobu <monyo@samba.org>\n"
"Language-Team: Samba Users Group Japan <sugj-tech@samba.gr.jp>\n"
"MIME-Version: 1.0\n"
"Content-Type: text/plain; charset=UTF-8\n"
"Content-Transfer-Encoding: 8bit\n"

#: ../web/swat.c:153
#, c-format
msgid "ERROR: Can't open %s"
msgstr "%s をオープンできません"

#: ../web/swat.c:241
msgid "Help"
msgstr "ヘルプ"

#: ../web/swat.c:247 ../web/swat.c:272 ../web/swat.c:293 ../web/swat.c:302 ../web/swat.c:311 ../web/swat.c:317 ../web/swat.c:329 ../web/swat.c:343
msgid "Set Default"
msgstr "デフォルト値"

#: ../web/swat.c:465
#, c-format
msgid "failed to open %s for writing"
msgstr "%s を書き込み用にオープンできません"

#: ../web/swat.c:488
#, c-format
msgid "Can't reload %s"
msgstr "%s を再読み込みできません\n"

# msgid "Logged in as <b>%s</b><p>\n"
#: ../web/swat.c:561
#, c-format
msgid "Logged in as <b>%s</b>"
msgstr "<b>%s</b>としてログイン"

#: ../web/swat.c:565
msgid "Home"
msgstr "ホーム"

#: ../web/swat.c:567
msgid "Globals"
msgstr "グローバル"

#: ../web/swat.c:568
msgid "Shares"
msgstr "ファイル共有"

#: ../web/swat.c:569
msgid "Printers"
msgstr "印刷共有"

#: ../web/swat.c:570
msgid "Wizard"
msgstr "ウィザード"

#: ../web/swat.c:574
msgid "Status"
msgstr "サーバの状態"

#: ../web/swat.c:575
msgid "View Config"
msgstr "現在の設定"

#: ../web/swat.c:577
msgid "Password Management"
msgstr "パスワード管理"

#: ../web/swat.c:587
msgid "Current View Is"
msgstr "現在の表示モード"

#: ../web/swat.c:588 ../web/swat.c:591
msgid "Basic"
msgstr "標準表示"

#: ../web/swat.c:589 ../web/swat.c:592
msgid "Advanced"
msgstr "詳細表示"

#: ../web/swat.c:590
msgid "Change View To"
msgstr "表示モードの変更"

#: ../web/swat.c:619
msgid "Current Config"
msgstr "現在の設定"

#: ../web/swat.c:623
msgid "Normal View"
msgstr "標準表示"

#: ../web/swat.c:625
msgid "Full View"
msgstr "完全表示"

#. Here we first set and commit all the parameters that were selected
#. in the previous screen.
#: ../web/swat.c:644
msgid "Wizard Parameter Edit Page"
msgstr "ウィザードによるパラメータ編集ページ"

#: ../web/swat.c:673
msgid "Note: smb.conf file has been read and rewritten"
msgstr "smb.conf ファイルが書き換えられました。"

#. Here we go ...
#: ../web/swat.c:779
msgid "Samba Configuration Wizard"
msgstr "Samba 設定ウィザード"

#: ../web/swat.c:783
msgid "The \"Rewrite smb.conf file\" button will clear the smb.conf file of all default values and of comments."
msgstr "「smb.conf の書換」ボタンを押すと smb.conf ファイル中のすべてのデフォルト値やコメントは削除されます。"

#: ../web/swat.c:784
msgid "The same will happen if you press the commit button."
msgstr "「commit」ボタンを押した場合にも同様の変更が行なわれます。"

#: ../web/swat.c:787
msgid "Rewrite smb.conf file"
msgstr "smb.conf の書換"

#: ../web/swat.c:788
msgid "Commit"
msgstr "設定を反映"

#: ../web/swat.c:789
msgid "Edit Parameter Values"
msgstr "各パラメータの編集"

#: ../web/swat.c:795
msgid "Server Type"
msgstr "サーバタイプ"

#: ../web/swat.c:796
msgid "Stand Alone"
msgstr "スタンドアロン"

#: ../web/swat.c:797
msgid "Domain Member"
msgstr "ドメインメンバ"

#: ../web/swat.c:798
msgid "Domain Controller"
msgstr "ドメインコントローラ"

#: ../web/swat.c:801
msgid "Unusual Type in smb.conf - Please Select New Mode"
msgstr "通常の形式ではない - 新しいモードを選択のこと"

#: ../web/swat.c:803
msgid "Configure WINS As"
msgstr "WINS"

#: ../web/swat.c:804
msgid "Not Used"
msgstr "使わない"

#: ../web/swat.c:805
msgid "Server for client use"
msgstr "サーバとして構成"

#: ../web/swat.c:806
msgid "Client of another WINS server"
msgstr "別の WINS サーバのクライアントとして構成"

#: ../web/swat.c:808
msgid "Remote WINS Server"
msgstr "別の WINS サーバ"

#: ../web/swat.c:819
msgid "Error: WINS Server Mode and WINS Support both set in smb.conf"
msgstr "エラー: wins server と wins support の両パラメータが smb.conf で指定されています"

#: ../web/swat.c:820
msgid "Please Select desired WINS mode above."
msgstr "いずれかの WINS モードを選択してください。"

#: ../web/swat.c:822
msgid "Expose Home Directories"
msgstr "ホームディレクトリの公開"

#: ../web/swat.c:837
msgid "The above configuration options will set multiple parameters and will generally assist with rapid Samba deployment."
msgstr "上記の設定オプションにより、複数のパラメータが同期して設定されるため、 Samba の運用を迅速に開始する上での助けとなるでしょう。"

#: ../web/swat.c:850
msgid "Global Parameters"
msgstr "Global パラメータ"

#: ../web/swat.c:878 ../web/swat.c:986 ../web/swat.c:1344
msgid "Commit Changes"
msgstr "変更を反映"

#: ../web/swat.c:882 ../web/swat.c:989 ../web/swat.c:1346
msgid "Reset Values"
msgstr "変更を取消"

#: ../web/swat.c:908
msgid "Share Parameters"
msgstr "ファイル共有 パラメータ"

#: ../web/swat.c:955
msgid "Choose Share"
msgstr "ファイル共有の選択"

#: ../web/swat.c:971
msgid "Delete Share"
msgstr "ファイル共有の削除"

#: ../web/swat.c:978
msgid "Create Share"
msgstr "ファイル共有の作成"

#: ../web/swat.c:1014
msgid "password change in demo mode rejected"
msgstr "デモ・モードでのパスワード変更はできません"

#: ../web/swat.c:1028
msgid "Can't setup password database vectors."
msgstr "パスワード・データベースが見つけられません"

#: ../web/swat.c:1056
msgid " Must specify \"User Name\" "
msgstr "「ユーザ名」欄に入力してください"

#: ../web/swat.c:1072
msgid " Must specify \"Old Password\" "
msgstr "「旧パスワード」欄に入力してください"

#: ../web/swat.c:1078
msgid " Must specify \"Remote Machine\" "
msgstr "「リモートマシン」欄に入力してください"

#: ../web/swat.c:1085
msgid " Must specify \"New, and Re-typed Passwords\" "
msgstr "「新パスワード」欄と「新パスワードの再入力」欄に入力してください"

#: ../web/swat.c:1091
msgid " Re-typed password didn't match new password "
msgstr "「新パスワードの再入力」欄の入力内容が「新パスワード」欄の入力と一致していません。"

#: ../web/swat.c:1124
#, c-format
msgid " The passwd for '%s' has been changed."
msgstr " %s のパスワードは変更されました。"

#: ../web/swat.c:1127
#, c-format
msgid " The passwd for '%s' has NOT been changed."
msgstr " '%s' のパスワードは変更されませんでした。"

#: ../web/swat.c:1152
msgid "Server Password Management"
msgstr "ローカルマシンのパスワード管理"

#.
#. * Create all the dialog boxes for data collection
#.
#: ../web/swat.c:1161 ../web/swat.c:1208
msgid "User Name"
msgstr "ユーザ名"

#: ../web/swat.c:1164 ../web/swat.c:1210
msgid "Old Password"
msgstr "旧パスワード"

#: ../web/swat.c:1167 ../web/swat.c:1212
msgid "New Password"
msgstr "新パスワード"

#: ../web/swat.c:1169 ../web/swat.c:1214
msgid "Re-type New Password"
msgstr "新パスワードの再入力"

#: ../web/swat.c:1177 ../web/swat.c:1225
msgid "Change Password"
msgstr "パスワード変更"

#: ../web/swat.c:1180
msgid "Add New User"
msgstr "新規ユーザ追加"

#: ../web/swat.c:1182
msgid "Delete User"
msgstr "ユーザの削除"

#: ../web/swat.c:1184
msgid "Disable User"
msgstr "ユーザの無効化"

#: ../web/swat.c:1186
msgid "Enable User"
msgstr "ユーザの有効化"

#: ../web/swat.c:1199
msgid "Client/Server Password Management"
msgstr "リモートマシンのパスワード管理"

#: ../web/swat.c:1216
msgid "Remote Machine"
msgstr "リモートマシン"

#: ../web/swat.c:1255
msgid "Printer Parameters"
msgstr "印刷共有 パラメータ"

#: ../web/swat.c:1257
msgid "Important Note:"
msgstr "*注"

#: ../web/swat.c:1258
msgid "Printer names marked with [*] in the Choose Printer drop-down box "
msgstr "名前の先頭に [*] がついたプリンタ"

#: ../web/swat.c:1259
msgid "are autoloaded printers from "
msgstr "は"

#: ../web/swat.c:1260
msgid "Printcap Name"
msgstr "printcap name パラメータ"

#: ../web/swat.c:1261
msgid "Attempting to delete these printers from SWAT will have no effect."
msgstr "から自動設定されたものですから、削除することはできません。"

#: ../web/swat.c:1310
msgid "Choose Printer"
msgstr "印刷共有の選択"

#: ../web/swat.c:1329
msgid "Delete Printer"
msgstr "印刷共有の削除"

#: ../web/swat.c:1336
msgid "Create Printer"
msgstr "印刷共有の作成"

#: ../web/statuspage.c:151
msgid "RDWR       "
msgstr "参照/更新  "

#: ../web/statuspage.c:153
msgid "WRONLY     "
msgstr "更新のみ   "

#: ../web/statuspage.c:155
msgid "RDONLY     "
msgstr "参照のみ   "

#: ../web/statuspage.c:329
msgid "Server Status"
msgstr "サーバの状態"

#: ../web/statuspage.c:334
msgid "Auto Refresh"
msgstr "自動更新の開始"

#: ../web/statuspage.c:335 ../web/statuspage.c:340
msgid "Refresh Interval: "
msgstr "更新間隔: "

#: ../web/statuspage.c:339
msgid "Stop Refreshing"
msgstr "自動更新の停止"

#: ../web/statuspage.c:348
msgid "version:"
msgstr "バージョン"

#: ../web/statuspage.c:351
msgid "smbd:"
msgstr ""

#: ../web/statuspage.c:351 ../web/statuspage.c:364 ../web/statuspage.c:378
msgid "running"
msgstr "実行中"

#: ../web/statuspage.c:351 ../web/statuspage.c:364 ../web/statuspage.c:378
msgid "not running"
msgstr "停止中"

#: ../web/statuspage.c:355
msgid "Stop smbd"
msgstr "smbd の停止"

#: ../web/statuspage.c:357
msgid "Start smbd"
msgstr "smbd の起動"

#: ../web/statuspage.c:359
msgid "Restart smbd"
msgstr "smbd の再起動"

#: ../web/statuspage.c:364
msgid "nmbd:"
msgstr ""

#: ../web/statuspage.c:368
msgid "Stop nmbd"
msgstr "nmbd の停止"

#: ../web/statuspage.c:370
msgid "Start nmbd"
msgstr "nmbd の起動"

#: ../web/statuspage.c:372
msgid "Restart nmbd"
msgstr "nmbd の再起動"

#: ../web/statuspage.c:378
msgid "winbindd:"
msgstr ""

#: ../web/statuspage.c:382
msgid "Stop winbindd"
msgstr "winbindd の停止"

#: ../web/statuspage.c:384
msgid "Start winbindd"
msgstr "winbindd の起動"

#: ../web/statuspage.c:386
msgid "Restart winbindd"
msgstr "winbindd の再起動"

#. stop, restart all
#: ../web/statuspage.c:395
msgid "Stop All"
msgstr "すべて停止"

#: ../web/statuspage.c:396
msgid "Restart All"
msgstr "すべて再起動"

#. start all
#: ../web/statuspage.c:400
msgid "Start All"
msgstr "すべて起動"

#: ../web/statuspage.c:407
msgid "Active Connections"
msgstr "接続中のクライアント"

#: ../web/statuspage.c:409 ../web/statuspage.c:422 ../web/statuspage.c:431
msgid "PID"
msgstr ""

#: ../web/statuspage.c:409 ../web/statuspage.c:422
msgid "Client"
msgstr "クライアント"

#: ../web/statuspage.c:409
msgid "IP address"
msgstr "IPアドレス"

#: ../web/statuspage.c:409 ../web/statuspage.c:422 ../web/statuspage.c:431
msgid "Date"
msgstr "日付"

#: ../web/statuspage.c:411
msgid "Kill"
msgstr "切断"

#: ../web/statuspage.c:419
msgid "Active Shares"
msgstr "接続中の共有"

#: ../web/statuspage.c:422
msgid "Share"
msgstr "共有名"

#: ../web/statuspage.c:422
msgid "User"
msgstr "ユーザ"

#: ../web/statuspage.c:422
msgid "Group"
msgstr "グループ"

#: ../web/statuspage.c:428
msgid "Open Files"
msgstr "使用中のファイル"

#: ../web/statuspage.c:431
msgid "UID"
msgstr ""

#: ../web/statuspage.c:431
msgid "Sharing"
msgstr "排他モード"

#: ../web/statuspage.c:431
msgid "R/W"
msgstr "参照/更新"

#: ../web/statuspage.c:431
msgid "Oplock"
msgstr ""

#: ../web/statuspage.c:431
msgid "File"
msgstr "ファイル名"

#: ../web/statuspage.c:438
msgid "Show Client in col 1"
msgstr "クライアント名を先頭に表示"

#: ../web/statuspage.c:439
msgid "Show PID in col 1"
msgstr "PIDを先頭に表示"

#: ../param/loadparm.c:907
msgid "Base Options"
msgstr "基本 オプション"

#: ../param/loadparm.c:1047
msgid "Security Options"
msgstr "セキュリティ オプション"

#: ../param/loadparm.c:1800
msgid "Logging Options"
msgstr "ロギング オプション"

#: ../param/loadparm.c:1929
msgid "Protocol Options"
msgstr "プロトコル オプション"

#: ../param/loadparm.c:2301
msgid "Tuning Options"
msgstr "チューニング オプション"

#: ../param/loadparm.c:2538
msgid "Printing Options"
msgstr "印刷 オプション"

#: ../param/loadparm.c:2858
msgid "Filename Handling"
msgstr "ファイル名の取扱"

#: ../param/loadparm.c:3088
msgid "Domain Options"
msgstr "ドメイン オプション"

#: ../param/loadparm.c:3100
msgid "Logon Options"
msgstr "ログオン オプション"

#: ../param/loadparm.c:3273
msgid "Browse Options"
msgstr "ブラウジング オプション"

#: ../param/loadparm.c:3384
msgid "WINS Options"
msgstr "WINS オプション"

#: ../param/loadparm.c:3432
msgid "Locking Options"
msgstr "ロッキング オプション"

#: ../param/loadparm.c:3552
msgid "Ldap Options"
msgstr "LDAP オプション"

#: ../param/loadparm.c:3708
#, fuzzy
msgid "EventLog Options"
msgstr "ログオン オプション"

#: ../param/loadparm.c:3720
msgid "Miscellaneous Options"
msgstr "その他のオプション"

#: ../param/loadparm.c:4301
msgid "VFS module options"
msgstr "VFS オプション"

#: ../param/loadparm.c:4323
#, fuzzy
msgid "MSDFS options"
msgstr "VFS オプション"

#: ../param/loadparm.c:4353
msgid "Winbind options"
msgstr "Winbind オプション"

#: ../utils/net.c:103
msgid "Enter machine password: "
msgstr ""

#: ../utils/net.c:107
msgid "Unable to write the machine account password in the secrets database"
msgstr ""

#: ../utils/net.c:111
msgid "Modified trust account password in secrets database\n"
msgstr ""

#: ../utils/net.c:115
msgid ""
"Machine account password change requires the -f flag.\n"
"Do NOT use this function unless you know what it does!\n"
"This function will change the ADS Domain member machine account password in the secrets.tdb file!\n"
msgstr ""

#: ../utils/net.c:150 ../utils/net.c:228
#, c-format
msgid "Unable to open secrets.tdb.  Can't fetch domain SID for name: %s\n"
msgstr ""

#: ../utils/net.c:163 ../utils/net.c:251
#, c-format
msgid "SID for domain %s is: %s\n"
msgstr ""

#: ../utils/net.c:175
msgid "usage: net setlocalsid S-1-5-21-x-y-z\n"
msgstr ""

#: ../utils/net.c:195
msgid "usage: net setdomainsid S-1-5-21-x-y-z\n"
msgstr ""

#: ../utils/net.c:213
msgid "usage: net getdomainsid\n"
msgstr ""

#: ../utils/net.c:238
msgid "Could not fetch local SID\n"
msgstr ""

#: ../utils/net.c:242
#, c-format
msgid "SID for local machine %s is: %s\n"
msgstr ""

#: ../utils/net.c:246
msgid "Could not fetch domain SID\n"
msgstr ""

#: ../utils/net.c:263
#, c-format
msgid "get_maxrid: Could not search %s\n"
msgstr ""

#: ../utils/net.c:297
msgid "usage: net maxrid\n"
msgstr ""

#: ../utils/net.c:302
msgid "can't get current maximum rid\n"
msgstr ""

#: ../utils/net.c:306
#, c-format
msgid "Currently used maximum rid: %d\n"
msgstr ""

#: ../utils/net.c:317
msgid "Run functions using RPC transport"
msgstr ""

#: ../utils/net.c:318
msgid "  Use 'net help rpc' to get more extensive information about 'net rpc' commands."
msgstr ""

#: ../utils/net.c:325
msgid "Run functions using RAP transport"
msgstr ""

#: ../utils/net.c:326
msgid "  Use 'net help rap' to get more extensive information about 'net rap' commands."
msgstr ""

#: ../utils/net.c:333
msgid "Run functions using ADS transport"
msgstr ""

#: ../utils/net.c:334
msgid "  Use 'net help ads' to get more extensive information about 'net ads' commands."
msgstr ""

#: ../utils/net.c:343
msgid "Functions on remote opened files"
msgstr ""

#: ../utils/net.c:344
msgid "  Use 'net help file' to get more information about 'net file' commands."
msgstr ""

#: ../utils/net.c:351
msgid "Functions on shares"
msgstr ""

#: ../utils/net.c:352
msgid "  Use 'net help share' to get more information about 'net share' commands."
msgstr ""

#: ../utils/net.c:359
msgid "Manage sessions"
msgstr ""

#: ../utils/net.c:360
msgid "  Use 'net help session' to get more information about 'net session' commands."
msgstr ""

#: ../utils/net.c:367
msgid "List servers in workgroup"
msgstr ""

#: ../utils/net.c:368
msgid "  Use 'net help server' to get more information about 'net server' commands."
msgstr ""

#: ../utils/net.c:375
msgid "List domains/workgroups on network"
msgstr ""

#: ../utils/net.c:376
msgid "  Use 'net help domain' to get more information about 'net domain' commands."
msgstr ""

#: ../utils/net.c:383
msgid "Modify printer queue"
msgstr ""

#: ../utils/net.c:384
msgid "  Use 'net help printq' to get more information about 'net printq' commands."
msgstr ""

#: ../utils/net.c:391
#, fuzzy
msgid "Manage users"
msgstr "ユーザの有効化"

#: ../utils/net.c:392
msgid "  Use 'net help user' to get more information about 'net user' commands."
msgstr ""

#: ../utils/net.c:399
msgid "Manage groups"
msgstr ""

#: ../utils/net.c:400
msgid "  Use 'net help group' to get more information about 'net group' commands."
msgstr ""

#: ../utils/net.c:407
msgid "Manage group mappings"
msgstr ""

#: ../utils/net.c:408
msgid "  Use 'net help groupmap' to get more information about 'net groupmap' commands."
msgstr ""

#: ../utils/net.c:415
msgid "Functions on the SAM database"
msgstr ""

#: ../utils/net.c:416
msgid "  Use 'net help sam' to get more information about 'net sam' commands."
msgstr ""

#: ../utils/net.c:423
msgid "Validate username and password"
msgstr ""

#: ../utils/net.c:424
msgid "  Use 'net help validate' to get more information about 'net validate' commands."
msgstr ""

#: ../utils/net.c:431
msgid "Modify group memberships"
msgstr ""

#: ../utils/net.c:432
msgid "  Use 'net help groupmember' to get more information about 'net groupmember' commands."
msgstr ""

#: ../utils/net.c:438
msgid "Execute remote command on a remote OS/2 server"
msgstr ""

#: ../utils/net.c:439
msgid "  Use 'net help admin' to get more information about 'net admin' commands."
msgstr ""

#: ../utils/net.c:445
msgid "List/modify running services"
msgstr ""

#: ../utils/net.c:446
msgid "  Use 'net help service' to get more information about 'net service' commands."
msgstr ""

#: ../utils/net.c:453
#, fuzzy
msgid "Change user password on target server"
msgstr "パスワード・データベースが見つけられません"

#: ../utils/net.c:454
msgid "  Use 'net help password' to get more information about 'net password' commands."
msgstr ""

#: ../utils/net.c:460
#, fuzzy
msgid "Change the trust password"
msgstr "パスワード変更"

#: ../utils/net.c:461
msgid "  Use 'net help changetrustpw' to get more information about 'net changetrustpw'."
msgstr ""

#: ../utils/net.c:467
#, fuzzy
msgid "Change the secret password"
msgstr "パスワード変更"

#: ../utils/net.c:468
msgid ""
"  net [options] changesecretpw\n"
"    Change the ADS domain member machine account password in secrets.tdb.\n"
"    Do NOT use this function unless you know what it does.\n"
"    Requires the -f flag to work."
msgstr ""

#: ../utils/net.c:477
msgid "Show/set time"
msgstr ""

#: ../utils/net.c:478
msgid "  Use 'net help time' to get more information about 'net time' commands."
msgstr ""

#: ../utils/net.c:484
msgid "Look up host names/IP addresses"
msgstr ""

#: ../utils/net.c:485
msgid "  Use 'net help lookup' to get more information about 'net lookup' commands."
msgstr ""

#: ../utils/net.c:491
msgid "Join a domain/AD"
msgstr ""

#: ../utils/net.c:492
msgid "  Use 'net help join' to get more information about 'net join'."
msgstr ""

#: ../utils/net.c:498
msgid "Join/unjoin (remote) machines to/from a domain/AD"
msgstr ""

#: ../utils/net.c:499
msgid "  Use 'net help dom' to get more information about 'net dom' commands."
msgstr ""

#: ../utils/net.c:505
msgid "Operate on the cache tdb file"
msgstr ""

#: ../utils/net.c:506
msgid "  Use 'net help cache' to get more information about 'net cache' commands."
msgstr ""

#: ../utils/net.c:512
msgid "Get the SID for the local domain"
msgstr ""

#: ../utils/net.c:513
msgid "  net getlocalsid"
msgstr ""

#: ../utils/net.c:518
msgid "Set the SID for the local domain"
msgstr ""

#: ../utils/net.c:519
msgid "  net setlocalsid S-1-5-21-x-y-z"
msgstr ""

#: ../utils/net.c:524
msgid "Set domain SID on member servers"
msgstr ""

#: ../utils/net.c:525
msgid "  net setdomainsid S-1-5-21-x-y-z"
msgstr ""

#: ../utils/net.c:530
msgid "Get domain SID on member servers"
msgstr ""

#: ../utils/net.c:531
msgid "  net getdomainsid"
msgstr ""

#: ../utils/net.c:536
msgid "Display the maximul RID currently used"
msgstr ""

#: ../utils/net.c:537
msgid "  net maxrid"
msgstr ""

#: ../utils/net.c:542
#, fuzzy
msgid "IDmap functions"
msgstr "ドメイン オプション"

#: ../utils/net.c:543
msgid "  Use 'net help idmap to get more information about 'net idmap' commands."
msgstr ""

#: ../utils/net.c:549
#, fuzzy
msgid "Display server status"
msgstr "サーバの状態"

#: ../utils/net.c:550
msgid "  Use 'net help status' to get more information about 'net status' commands."
msgstr ""

#: ../utils/net.c:556
msgid "Manage user-modifiable shares"
msgstr ""

#: ../utils/net.c:557
msgid "  Use 'net help usershare to get more information about 'net usershare' commands."
msgstr ""

#: ../utils/net.c:563
msgid "Display list of all users with SID"
msgstr ""

#: ../utils/net.c:564
msgid "  Use 'net help usersidlist' to get more information about 'net usersidlist'."
msgstr ""

#: ../utils/net.c:570
msgid "Manage Samba registry based configuration"
msgstr ""

#: ../utils/net.c:571
msgid "  Use 'net help conf' to get more information about 'net conf' commands."
msgstr ""

#: ../utils/net.c:577
msgid "Manage the Samba registry"
msgstr ""

#: ../utils/net.c:578
msgid "  Use 'net help registry' to get more information about 'net registry' commands."
msgstr ""

#: ../utils/net.c:584
msgid "Open a lua interpreter"
msgstr ""

#: ../utils/net.c:585
msgid "  Use 'net help lua' to get more information about 'net lua' commands."
msgstr ""

#: ../utils/net.c:591
msgid "Process Win32 *.evt eventlog files"
msgstr ""

#: ../utils/net.c:592
msgid "  Use 'net help eventlog' to get more information about 'net eventlog' commands."
msgstr ""

#: ../utils/net.c:600
msgid "Manage AFS tokens"
msgstr ""

#: ../utils/net.c:601
msgid "  Use 'net help afs' to get more information about 'net afs' commands."
msgstr ""

#: ../utils/net.c:609
msgid "Print usage information"
msgstr ""

#: ../utils/net.c:610
msgid "  Use 'net help help' to list usage information for 'net' commands."
msgstr ""

#: ../utils/net.c:639
msgid "Encrypt SMB transport (UNIX extended servers only)"
msgstr ""

#: ../utils/net.c:703
msgid ""
"\n"
"Invalid ip address specified\n"
msgstr ""

#: ../utils/net.c:718
#, c-format
msgid ""
"\n"
"Invalid option %s: %s\n"
msgstr ""

#: ../utils/net_ads.c:52 ../utils/net_ads.c:392
msgid "CLDAP query failed!\n"
msgstr ""

#: ../utils/net_ads.c:56
#, fuzzy, c-format
msgid ""
"Information for Domain Controller: %s\n"
"\n"
msgstr "ドメインコントローラ"

#: ../utils/net_ads.c:59
msgid "Response Type: "
msgstr ""

#: ../utils/net_ads.c:72
#, c-format
msgid "GUID: %s\n"
msgstr ""

#: ../utils/net_ads.c:74
#, c-format
msgid ""
"Flags:\n"
"\tIs a PDC:                                   %s\n"
"\tIs a GC of the forest:                      %s\n"
"\tIs an LDAP server:                          %s\n"
"\tSupports DS:                                %s\n"
"\tIs running a KDC:                           %s\n"
"\tIs running time services:                   %s\n"
"\tIs the closest DC:                          %s\n"
"\tIs writable:                                %s\n"
"\tHas a hardware clock:                       %s\n"
"\tIs a non-domain NC serviced by LDAP server: %s\n"
"\tIs NT6 DC that has some secrets:            %s\n"
"\tIs NT6 DC that has all secrets:             %s\n"
msgstr ""

#: ../utils/net_ads.c:87 ../utils/net_ads.c:88 ../utils/net_ads.c:89 ../utils/net_ads.c:90 ../utils/net_ads.c:91 ../utils/net_ads.c:92 ../utils/net_ads.c:93 ../utils/net_ads.c:94 ../utils/net_ads.c:95 ../utils/net_ads.c:96 ../utils/net_ads.c:97
#: ../utils/net_ads.c:98
msgid "yes"
msgstr ""

#: ../utils/net_ads.c:87 ../utils/net_ads.c:88 ../utils/net_ads.c:89 ../utils/net_ads.c:90 ../utils/net_ads.c:91 ../utils/net_ads.c:92 ../utils/net_ads.c:93 ../utils/net_ads.c:94 ../utils/net_ads.c:95 ../utils/net_ads.c:96 ../utils/net_ads.c:97
#: ../utils/net_ads.c:98
msgid "no"
msgstr ""

#: ../utils/net_ads.c:101
#, c-format
msgid "Forest:\t\t\t%s\n"
msgstr ""

#: ../utils/net_ads.c:102
#, c-format
msgid "Domain:\t\t\t%s\n"
msgstr ""

#: ../utils/net_ads.c:103
#, fuzzy, c-format
msgid "Domain Controller:\t%s\n"
msgstr "ドメインコントローラ"

#: ../utils/net_ads.c:105
#, c-format
msgid "Pre-Win2k Domain:\t%s\n"
msgstr ""

#: ../utils/net_ads.c:106
#, c-format
msgid "Pre-Win2k Hostname:\t%s\n"
msgstr ""

#: ../utils/net_ads.c:108
#, fuzzy, c-format
msgid "User name:\t%s\n"
msgstr "ユーザ名"

#: ../utils/net_ads.c:110
#, fuzzy, c-format
msgid "Server Site Name :\t\t%s\n"
msgstr "サーバの状態"

#: ../utils/net_ads.c:111
#, c-format
msgid "Client Site Name :\t\t%s\n"
msgstr ""

#: ../utils/net_ads.c:113
#, fuzzy, c-format
msgid "NT Version: %d\n"
msgstr "バージョン"

#: ../utils/net_ads.c:114
#, c-format
msgid "LMNT Token: %.2x\n"
msgstr ""

#: ../utils/net_ads.c:115
#, c-format
msgid "LM20 Token: %.2x\n"
msgstr ""

#: ../utils/net_ads.c:130
msgid ""
"Usage:\n"
"net ads lookup\n"
"    Find the ADS DC using CLDAP lookup.\n"
msgstr ""

#: ../utils/net_ads.c:137 ../utils/net_ads.c:381
msgid "Didn't find the cldap server!\n"
msgstr ""

#: ../utils/net_ads.c:160
msgid ""
"Usage:\n"
"net ads info\n"
"    Display information about an Active Directory server.\n"
msgstr ""

#: ../utils/net_ads.c:168 ../utils/net_ads.c:173
msgid "Didn't find the ldap server!\n"
msgstr ""

#: ../utils/net_ads.c:182
msgid "Failed to get server's current time!\n"
msgstr ""

#: ../utils/net_ads.c:187
#, c-format
msgid "LDAP server: %s\n"
msgstr ""

#: ../utils/net_ads.c:188
#, c-format
msgid "LDAP server name: %s\n"
msgstr ""

#: ../utils/net_ads.c:189
#, c-format
msgid "Realm: %s\n"
msgstr ""

#: ../utils/net_ads.c:190
#, c-format
msgid "Bind Path: %s\n"
msgstr ""

#: ../utils/net_ads.c:191
#, c-format
msgid "LDAP port: %d\n"
msgstr ""

#: ../utils/net_ads.c:192
#, fuzzy, c-format
msgid "Server time: %s\n"
msgstr "サーバの状態"

#: ../utils/net_ads.c:195
#, c-format
msgid "KDC server: %s\n"
msgstr ""

#: ../utils/net_ads.c:196
#, c-format
msgid "Server time offset: %d\n"
msgstr ""

#: ../utils/net_ads.c:374
msgid ""
"Usage:\n"
"net ads workgroup\n"
"    Print the workgroup name\n"
msgstr ""

#: ../utils/net_ads.c:397
#, c-format
msgid "Workgroup: %s\n"
msgstr ""

#: ../utils/net_ads.c:458
#, c-format
msgid "ads_user_add: %s\n"
msgstr ""

#: ../utils/net_ads.c:463
#, c-format
msgid "ads_user_add: User %s already exists\n"
msgstr ""

#: ../utils/net_ads.c:477
#, c-format
msgid "Could not add user %s: %s\n"
msgstr ""

#: ../utils/net_ads.c:484 ../utils/net_ads.c:497
#, fuzzy, c-format
msgid "User %s added\n"
msgstr "ユーザ名"

#. password didn't set, delete account
#: ../utils/net_ads.c:503
#, c-format
msgid "Could not add user %s. Error setting password %s\n"
msgstr ""

#: ../utils/net_ads.c:551
#, c-format
msgid "ads_user_info: failed to escape user %s\n"
msgstr ""

#: ../utils/net_ads.c:569
#, c-format
msgid "ads_search: %s\n"
msgstr ""

#: ../utils/net_ads.c:575
msgid "ads_pull_uint32 failed\n"
msgstr ""

#: ../utils/net_ads.c:582
#, c-format
msgid "ads_domain_sid: %s\n"
msgstr ""

#: ../utils/net_ads.c:642
#, c-format
msgid "User %s does not exist.\n"
msgstr ""

#: ../utils/net_ads.c:652
#, c-format
msgid "User %s deleted\n"
msgstr ""

#: ../utils/net_ads.c:656
#, c-format
msgid "Error deleting user %s: %s\n"
msgstr ""

#: ../utils/net_ads.c:669
#, fuzzy
msgid "Add an AD user"
msgstr "新規ユーザ追加"

#: ../utils/net_ads.c:670
msgid ""
"net ads user add\n"
"    Add an AD user"
msgstr ""

#: ../utils/net_ads.c:677
msgid "Display information about an AD user"
msgstr ""

#: ../utils/net_ads.c:678
msgid ""
"net ads user info\n"
"    Display information about an AD user"
msgstr ""

#: ../utils/net_ads.c:685
#, fuzzy
msgid "Delete an AD user"
msgstr "ユーザの削除"

#: ../utils/net_ads.c:686
msgid ""
"net ads user delete\n"
"    Delete an AD user"
msgstr ""

#: ../utils/net_ads.c:699
msgid ""
"Usage:\n"
"net ads user\n"
"    List AD users\n"
msgstr ""

#: ../utils/net_ads.c:711
msgid ""
"\n"
"User name             Comment\n"
"-----------------------------\n"
msgstr ""

#: ../utils/net_ads.c:751
#, c-format
msgid "ads_group_add: %s\n"
msgstr ""

#: ../utils/net_ads.c:756
#, c-format
msgid "ads_group_add: Group %s already exists\n"
msgstr ""

#: ../utils/net_ads.c:769
#, c-format
msgid "Group %s added\n"
msgstr ""

#: ../utils/net_ads.c:772
#, c-format
msgid "Could not add group %s: %s\n"
msgstr ""

#: ../utils/net_ads.c:801
#, c-format
msgid "Group %s does not exist.\n"
msgstr ""

#: ../utils/net_ads.c:811
#, c-format
msgid "Group %s deleted\n"
msgstr ""

#: ../utils/net_ads.c:815
#, c-format
msgid "Error deleting group %s: %s\n"
msgstr ""

#: ../utils/net_ads.c:828
msgid "Add an AD group"
msgstr ""

#: ../utils/net_ads.c:829
msgid ""
"net ads group add\n"
"    Add an AD group"
msgstr ""

#: ../utils/net_ads.c:836
#, fuzzy
msgid "Delete an AD group"
msgstr "ファイル共有の削除"

#: ../utils/net_ads.c:837
msgid ""
"net ads group delete\n"
"    Delete an AD group"
msgstr ""

#: ../utils/net_ads.c:850
msgid ""
"Usage:\n"
"net ads group\n"
"    List AD groups\n"
msgstr ""

#: ../utils/net_ads.c:862
msgid ""
"\n"
"Group name            Comment\n"
"-----------------------------\n"
msgstr ""

#: ../utils/net_ads.c:884
msgid ""
"Usage:\n"
"net ads status\n"
"    Display machine account details\n"
msgstr ""

#: ../utils/net_ads.c:896
#, c-format
msgid "ads_find_machine_acct: %s\n"
msgstr ""

#: ../utils/net_ads.c:902
#, c-format
msgid "No machine account for '%s' found\n"
msgstr ""

#: ../utils/net_ads.c:926
msgid ""
"Usage:\n"
"net ads leave\n"
"    Leave an AD domain\n"
msgstr ""

#: ../utils/net_ads.c:933
msgid "No realm set, are we joined ?\n"
msgstr ""

#: ../utils/net_ads.c:938 ../utils/net_ads.c:1260
msgid "Could not initialise talloc context.\n"
msgstr ""

#: ../utils/net_ads.c:948
msgid "Could not initialise unjoin context.\n"
msgstr ""

#: ../utils/net_ads.c:968
#, c-format
msgid "Failed to leave domain: %s\n"
msgstr ""

#: ../utils/net_ads.c:975
#, c-format
msgid "Deleted account for '%s' in realm '%s'\n"
msgstr ""

#: ../utils/net_ads.c:982
#, c-format
msgid "Disabled account for '%s' in realm '%s'\n"
msgstr ""

#. Based on what we requseted, we shouldn't get here, but if
#. we did, it means the secrets were removed, and therefore
#. we have left the domain
#: ../utils/net_ads.c:991
#, c-format
msgid "Machine '%s' Left domain '%s'\n"
msgstr ""

#: ../utils/net_ads.c:1035
msgid ""
"Usage:\n"
"net ads testjoin\n"
"    Test if the existing join is ok\n"
msgstr ""

#: ../utils/net_ads.c:1044
#, c-format
msgid "Join to domain is not valid: %s\n"
msgstr ""

#: ../utils/net_ads.c:1049
#, c-format
msgid "Join is OK\n"
msgstr ""

#: ../utils/net_ads.c:1060
msgid "Host is not configured as a member server.\n"
msgstr ""

#: ../utils/net_ads.c:1065
#, c-format
msgid "Our netbios name can be at most 15 chars long, \"%s\" is %u chars long\n"
msgstr ""

#: ../utils/net_ads.c:1072
#, c-format
msgid "realm must be set in in %s for ADS join to succeed.\n"
msgstr ""

#: ../utils/net_ads.c:1105
#, c-format
msgid "No DNS domain configured for %s. Unable to perform DNS Update.\n"
msgstr ""

#: ../utils/net_ads.c:1212
msgid ""
"net ads join [options]\n"
"Valid options:\n"
msgstr ""

#: ../utils/net_ads.c:1214
msgid ""
"   createupn[=UPN]    Set the userPrincipalName attribute during the join.\n"
"                      The deault UPN is in the form host/netbiosname@REALM.\n"
msgstr ""

#: ../utils/net_ads.c:1216
msgid ""
"   createcomputer=OU  Precreate the computer account in a specific OU.\n"
"                      The OU string read from top to bottom without RDNs and delimited by a '/'.\n"
"                      E.g. \"createcomputer=Computers/Servers/Unix\"\n"
"                      NB: A backslash '\\' is used as escape at multiple levels and may\n"
"                          need to be doubled or even quadrupled.  It is not used as a separator.\n"
msgstr ""

#: ../utils/net_ads.c:1221
msgid "   osName=string      Set the operatingSystem attribute during the join.\n"
msgstr ""

#: ../utils/net_ads.c:1222
msgid ""
"   osVer=string       Set the operatingSystemVersion attribute during the join.\n"
"                      NB: osName and osVer must be specified together for either to take effect.\n"
"                          Also, the operatingSystemService attribute is also set when along with\n"
"                          the two other attributes.\n"
msgstr ""

#: ../utils/net_ads.c:1254
msgid "Invalid configuration.  Exiting....\n"
msgstr ""

#: ../utils/net_ads.c:1283
msgid "Please supply a valid OU path.\n"
msgstr ""

#: ../utils/net_ads.c:1290
msgid "Please supply a operating system name.\n"
msgstr ""

#: ../utils/net_ads.c:1297
msgid "Please supply a valid operating system version.\n"
msgstr ""

#: ../utils/net_ads.c:1308
msgid "Please supply a valid domain name\n"
msgstr ""

#: ../utils/net_ads.c:1339
#, c-format
msgid ""
"The workgroup in %s does not match the short\n"
"domain name obtained from the server.\n"
"Using the name [%s] from the server.\n"
"You should set \"workgroup = %s\" in %s.\n"
msgstr ""

#: ../utils/net_ads.c:1347
#, c-format
msgid "Using short domain name -- %s\n"
msgstr ""

#: ../utils/net_ads.c:1350
#, c-format
msgid "Joined '%s' to realm '%s'\n"
msgstr ""

#: ../utils/net_ads.c:1353
#, c-format
msgid "Joined '%s' to domain '%s'\n"
msgstr ""

#: ../utils/net_ads.c:1377 ../utils/net_ads.c:1433
msgid "DNS update failed!\n"
msgstr ""

#. issue an overall failure message at the end.
#: ../utils/net_ads.c:1391
#, c-format
msgid "Failed to join domain: %s\n"
msgstr ""

#: ../utils/net_ads.c:1414
msgid ""
"Usage:\n"
"net ads dns register\n"
"    Register hostname with DNS\n"
msgstr ""

#: ../utils/net_ads.c:1421
msgid "Could not initialise talloc context\n"
msgstr ""

#: ../utils/net_ads.c:1439
msgid "Successfully registered hostname with DNS\n"
msgstr ""

#: ../utils/net_ads.c:1447
msgid "DNS update support not enabled at compile time!\n"
msgstr ""

#: ../utils/net_ads.c:1466
msgid ""
"Usage:\n"
"net ads dns gethostbyname <server> <name>\n"
"  Look up hostname from the AD\n"
"    server\tName server to use\n"
"    name\tName to look up\n"
msgstr ""

#: ../utils/net_ads.c:1476
#, c-format
msgid "do_gethostbyname returned %d\n"
msgstr ""

#: ../utils/net_ads.c:1488
msgid "Add host dns entry to AD"
msgstr ""

#: ../utils/net_ads.c:1489
msgid ""
"net ads dns register\n"
"    Add host dns entry to AD"
msgstr ""

#: ../utils/net_ads.c:1496
msgid "Look up host"
msgstr ""

#: ../utils/net_ads.c:1497
msgid ""
"net ads dns gethostbyname\n"
"    Look up host"
msgstr ""

#: ../utils/net_ads.c:1512
msgid ""
"\n"
"net ads printer search <printer>\n"
"\tsearch for a printer in the directory\n"
"\n"
"net ads printer info <printer> <server>\n"
"\tlookup info in directory for printer on server\n"
"\t(note: printer defaults to \"*\", server defaults to local)\n"
"\n"
"net ads printer publish <printername>\n"
"\tpublish printer in directory\n"
"\t(note: printer name is required)\n"
"\n"
"net ads printer remove <printername>\n"
"\tremove printer from directory\n"
"\t(note: printer name is required)\n"
msgstr ""

#: ../utils/net_ads.c:1536
msgid ""
"Usage:\n"
"net ads printer search\n"
"    List printers in the AD\n"
msgstr ""

#: ../utils/net_ads.c:1549
#, c-format
msgid "ads_find_printer: %s\n"
msgstr ""

#: ../utils/net_ads.c:1556
msgid "No results found\n"
msgstr ""

#: ../utils/net_ads.c:1576
msgid ""
"Usage:\n"
"net ads printer info [printername [servername]]\n"
"  Display printer info from AD\n"
"    printername\tPrinter name or wildcard\n"
"    servername\tName of the print server\n"
msgstr ""

#: ../utils/net_ads.c:1603
#, c-format
msgid "Server '%s' not found: %s\n"
msgstr ""

#: ../utils/net_ads.c:1611 ../utils/net_ads.c:1794
#, c-format
msgid "Printer '%s' not found\n"
msgstr ""

#: ../utils/net_ads.c:1640
msgid ""
"Usage:\n"
"net ads printer publish <printername> [servername]\n"
"  Publish printer in AD\n"
"    printername\tName of the printer\n"
"    servername\tName of the print server\n"
msgstr ""

#: ../utils/net_ads.c:1675
#, c-format
msgid "Unable to open a connnection to %s to obtain data for %s\n"
msgstr ""

#: ../utils/net_ads.c:1688
#, c-format
msgid "Could not find machine account for server %s\n"
msgstr ""

#: ../utils/net_ads.c:1704 ../utils/net_ads.c:1713
msgid "Internal error, out of memory!"
msgstr ""

#: ../utils/net_ads.c:1724
#, c-format
msgid "Unable to open a connnection to the spoolss pipe on %s\n"
msgstr ""

#: ../utils/net_ads.c:1766
msgid ""
"Usage:\n"
"net ads printer remove <printername> [servername]\n"
"  Remove a printer from the AD\n"
"    printername\tName of the printer\n"
"    servername\tName of the print server\n"
msgstr ""

#: ../utils/net_ads.c:1787
#, c-format
msgid "ads_find_printer_on_server: %s\n"
msgstr ""

#: ../utils/net_ads.c:1806
#, c-format
msgid "ads_del_dn: %s\n"
msgstr ""

#: ../utils/net_ads.c:1822
msgid "Search for a printer"
msgstr ""

#: ../utils/net_ads.c:1823
msgid ""
"net ads printer search\n"
"    Search for a printer"
msgstr ""

#: ../utils/net_ads.c:1830
msgid "Display printer information"
msgstr ""

#: ../utils/net_ads.c:1831
msgid ""
"net ads printer info\n"
"    Display printer information"
msgstr ""

#: ../utils/net_ads.c:1838
msgid "Publish a printer"
msgstr ""

#: ../utils/net_ads.c:1839
msgid ""
"net ads printer publish\n"
"    Publish a printer"
msgstr ""

#: ../utils/net_ads.c:1846
#, fuzzy
msgid "Delete a printer"
msgstr "印刷共有の削除"

#: ../utils/net_ads.c:1847
msgid ""
"net ads printer remove\n"
"    Delete a printer"
msgstr ""

#: ../utils/net_ads.c:1869
msgid ""
"Usage:\n"
"net ads password <username>\n"
"  Change password for user\n"
"    username\tName of user to change password for\n"
msgstr ""

#: ../utils/net_ads.c:1877
msgid "You must supply an administrator username/password\n"
msgstr ""

#: ../utils/net_ads.c:1883
msgid "ERROR: You must say which username to change password for\n"
msgstr ""

#: ../utils/net_ads.c:1915
msgid "Didn't find the kerberos server!\n"
msgstr ""

#: ../utils/net_ads.c:1923
#, c-format
msgid "Enter new password for %s:"
msgstr ""

#: ../utils/net_ads.c:1933 ../utils/net_ads.c:1982
#, fuzzy, c-format
msgid "Password change failed: %s\n"
msgstr "パスワード管理"

#: ../utils/net_ads.c:1938
#, fuzzy, c-format
msgid "Password change for %s completed.\n"
msgstr "デモ・モードでのパスワード変更はできません"

#: ../utils/net_ads.c:1952
msgid ""
"Usage:\n"
"net ads changetrustpw\n"
"    Change the machine account's trust password\n"
msgstr ""

#: ../utils/net_ads.c:1977
#, c-format
msgid "Changing password for principal: %s\n"
msgstr ""

#: ../utils/net_ads.c:1988
#, c-format
msgid "Password change for principal %s succeeded.\n"
msgstr ""

#: ../utils/net_ads.c:1991
msgid "Attempting to update system keytab with new password.\n"
msgstr ""

#: ../utils/net_ads.c:1993
msgid "Failed to update system keytab.\n"
msgstr ""

#: ../utils/net_ads.c:2009
msgid ""
"\n"
"net ads search <expression> <attributes...>\n"
"\n"
"Perform a raw LDAP search on a ADS server and dump the results.\n"
"The expression is a standard LDAP search expression, and the\n"
"attributes are a list of LDAP fields to show in the results.\n"
"\n"
"Example: net ads search '(objectCategory=group)' sAMAccountName\n"
"\n"
msgstr ""

#: ../utils/net_ads.c:2046 ../utils/net_ads.c:2107 ../utils/net_ads.c:2171
#, c-format
msgid "search failed: %s\n"
msgstr ""

#: ../utils/net_ads.c:2051 ../utils/net_ads.c:2176
#, c-format
msgid ""
"Got %d replies\n"
"\n"
msgstr ""

#: ../utils/net_ads.c:2069
msgid ""
"\n"
"net ads dn <dn> <attributes...>\n"
"\n"
"perform a raw LDAP search on a ADS server and dump the results\n"
"The DN standard LDAP DN, and the attributes are a list of LDAP fields \n"
"to show in the results\n"
"\n"
"Example: net ads dn 'CN=administrator,CN=Users,DC=my,DC=domain' sAMAccountName\n"
"\n"
"Note: the DN must be provided properly escaped. See RFC 4514 for details\n"
"\n"
msgstr ""

#: ../utils/net_ads.c:2129
msgid ""
"\n"
"net ads sid <sid> <attributes...>\n"
"\n"
"perform a raw LDAP search on a ADS server and dump the results\n"
"The SID is in string format, and the attributes are a list of LDAP fields \n"
"to show in the results\n"
"\n"
"Example: net ads sid 'S-1-5-32' distinguishedName\n"
"\n"
msgstr ""

#: ../utils/net_ads.c:2164
msgid "could not convert sid\n"
msgstr ""

#: ../utils/net_ads.c:2193
msgid ""
"Usage:\n"
"net ads keytab flush\n"
"    Delete the whole keytab\n"
msgstr ""

#: ../utils/net_ads.c:2214
msgid ""
"Usage:\n"
"net ads keytab add <principal> [principal ...]\n"
"  Add principals to local keytab\n"
"    principal\tKerberos principal to add to keytab\n"
msgstr ""

#: ../utils/net_ads.c:2222
msgid "Processing principals to add...\n"
msgstr ""

#: ../utils/net_ads.c:2239
msgid ""
"Usage:\n"
"net ads keytab create\n"
"    Create new default keytab\n"
msgstr ""

#: ../utils/net_ads.c:2258
msgid ""
"Usage:\n"
"net ads keytab list [keytab]\n"
"  List a local keytab\n"
"    keytab\tKeytab to list\n"
msgstr ""

#: ../utils/net_ads.c:2280
msgid "Add a service principal"
msgstr ""

#: ../utils/net_ads.c:2281
msgid ""
"net ads keytab add\n"
"    Add a service principal"
msgstr ""

#: ../utils/net_ads.c:2288
#, fuzzy
msgid "Create a fresh keytab"
msgstr "ファイル共有の作成"

#: ../utils/net_ads.c:2289
msgid ""
"net ads keytab create\n"
"    Create a fresh keytab"
msgstr ""

#: ../utils/net_ads.c:2296
msgid "Remove all keytab entries"
msgstr ""

#: ../utils/net_ads.c:2297
msgid ""
"net ads keytab flush\n"
"    Remove all keytab entries"
msgstr ""

#: ../utils/net_ads.c:2304
msgid "List a keytab"
msgstr ""

#: ../utils/net_ads.c:2305
msgid ""
"net ads keytab list\n"
"    List a keytab"
msgstr ""

#: ../utils/net_ads.c:2312
msgid ""
"\n"
"Warning: \"kerberos method\" must be set to a keytab method to use keytab functions.\n"
msgstr ""

#: ../utils/net_ads.c:2324
msgid ""
"Usage:\n"
"net ads kerberos renew\n"
"    Renew TGT from existing credential cache\n"
msgstr ""

#: ../utils/net_ads.c:2332
#, c-format
msgid "failed to renew kerberos ticket: %s\n"
msgstr ""

#: ../utils/net_ads.c:2347
msgid ""
"Usage:\n"
"net ads kerberos pac\n"
"    Dump the Kerberos PAC\n"
msgstr ""

#: ../utils/net_ads.c:2372
#, c-format
msgid "failed to query kerberos PAC: %s\n"
msgstr ""

#: ../utils/net_ads.c:2381
#, c-format
msgid "The Pac: %s\n"
msgstr ""

#: ../utils/net_ads.c:2397
msgid ""
"Usage:\n"
"net ads kerberos kinit\n"
"    Get Ticket Granting Ticket (TGT) for the user\n"
msgstr ""

#: ../utils/net_ads.c:2421
#, c-format
msgid "failed to kinit password: %s\n"
msgstr ""

#: ../utils/net_ads.c:2435
msgid "Retrieve Ticket Granting Ticket (TGT)"
msgstr ""

#: ../utils/net_ads.c:2436
msgid ""
"net ads kerberos kinit\n"
"    Receive Ticket Granting Ticket (TGT)"
msgstr ""

#: ../utils/net_ads.c:2443
msgid "Renew Ticket Granting Ticket from credential cache"
msgstr ""

#: ../utils/net_ads.c:2444
msgid ""
"net ads kerberos renew\n"
"    Renew Ticket Granting Ticket (TGT) from credential cache"
msgstr ""

#: ../utils/net_ads.c:2452
msgid "Dump Kerberos PAC"
msgstr ""

#: ../utils/net_ads.c:2453
msgid ""
"net ads kerberos pac\n"
"    Dump Kerberos PAC"
msgstr ""

#: ../utils/net_ads.c:2469
msgid "Display details on remote ADS server"
msgstr ""

#: ../utils/net_ads.c:2470
msgid ""
"net ads info\n"
"    Display details on remote ADS server"
msgstr ""

#: ../utils/net_ads.c:2477
msgid "Join the local machine to ADS realm"
msgstr ""

#: ../utils/net_ads.c:2478
msgid ""
"net ads join\n"
"    Join the local machine to ADS realm"
msgstr ""

#: ../utils/net_ads.c:2485
msgid "Validate machine account"
msgstr ""

#: ../utils/net_ads.c:2486
msgid ""
"net ads testjoin\n"
"    Validate machine account"
msgstr ""

#: ../utils/net_ads.c:2493
msgid "Remove the local machine from ADS"
msgstr ""

#: ../utils/net_ads.c:2494
msgid ""
"net ads leave\n"
"    Remove the local machine from ADS"
msgstr ""

#: ../utils/net_ads.c:2501
msgid "Display machine account details"
msgstr ""

#: ../utils/net_ads.c:2502
msgid ""
"net ads status\n"
"    Display machine account details"
msgstr ""

#: ../utils/net_ads.c:2509
msgid "List/modify users"
msgstr ""

#: ../utils/net_ads.c:2510
msgid ""
"net ads user\n"
"    List/modify users"
msgstr ""

#: ../utils/net_ads.c:2517
msgid "List/modify groups"
msgstr ""

#: ../utils/net_ads.c:2518
msgid ""
"net ads group\n"
"    List/modify groups"
msgstr ""

#: ../utils/net_ads.c:2525
msgid "Issue dynamic DNS update"
msgstr ""

#: ../utils/net_ads.c:2526
msgid ""
"net ads dns\n"
"    Issue dynamic DNS update"
msgstr ""

#: ../utils/net_ads.c:2533
#, fuzzy
msgid "Change user passwords"
msgstr "パスワード変更"

#: ../utils/net_ads.c:2534
msgid ""
"net ads password\n"
"    Change user passwords"
msgstr ""

#: ../utils/net_ads.c:2541
#, fuzzy
msgid "Change trust account password"
msgstr "パスワード変更"

#: ../utils/net_ads.c:2542
msgid ""
"net ads changetrustpw\n"
"    Change trust account password"
msgstr ""

#: ../utils/net_ads.c:2549
msgid "List/modify printer entries"
msgstr ""

#: ../utils/net_ads.c:2550
msgid ""
"net ads printer\n"
"    List/modify printer entries"
msgstr ""

#: ../utils/net_ads.c:2557
msgid "Issue LDAP search using filter"
msgstr ""

#: ../utils/net_ads.c:2558
msgid ""
"net ads search\n"
"    Issue LDAP search using filter"
msgstr ""

#: ../utils/net_ads.c:2565
msgid "Issue LDAP search by DN"
msgstr ""

#: ../utils/net_ads.c:2566
msgid ""
"net ads dn\n"
"    Issue LDAP search by DN"
msgstr ""

#: ../utils/net_ads.c:2573
msgid "Issue LDAP search by SID"
msgstr ""

#: ../utils/net_ads.c:2574
msgid ""
"net ads sid\n"
"    Issue LDAP search by SID"
msgstr ""

#: ../utils/net_ads.c:2581
msgid "Display workgroup name"
msgstr ""

#: ../utils/net_ads.c:2582
msgid ""
"net ads workgroup\n"
"    Display the workgroup name"
msgstr ""

#: ../utils/net_ads.c:2589
msgid "Perfom CLDAP query on DC"
msgstr ""

#: ../utils/net_ads.c:2590
msgid ""
"net ads lookup\n"
"    Find the ADS DC using CLDAP lookups"
msgstr ""

#: ../utils/net_ads.c:2597
msgid "Manage local keytab file"
msgstr ""

#: ../utils/net_ads.c:2598
msgid ""
"net ads keytab\n"
"    Manage local keytab file"
msgstr ""

#: ../utils/net_ads.c:2605
msgid "Manage group policy objects"
msgstr ""

#: ../utils/net_ads.c:2606
msgid ""
"net ads gpo\n"
"    Manage group policy objects"
msgstr ""

#: ../utils/net_ads.c:2613
msgid "Manage kerberos keytab"
msgstr ""

#: ../utils/net_ads.c:2614
msgid ""
"net ads kerberos\n"
"    Manage kerberos keytab"
msgstr ""

#: ../utils/net_ads.c:2627
msgid "ADS support not compiled in\n"
msgstr ""
