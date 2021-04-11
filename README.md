# jvnchecker
`jvnchecker` は、[JVNDB](https://jvndb.jvn.jp/index.html) から脆弱性情報を検索するCLIツールです。

# installation
`pip install .`

# usage
```
# jvnchecker
usage: jvnchecker [-h] [-o OUTPUT] [--json] [-v] {vendor,list,detail} ...

positional arguments:
  {vendor,list,detail}
    vendor              ベンダー名からベンダーIDを検索します
    list                脆弱性概要の一覧を取得し、影響するバージョンを返します
    detail              JVNDBのIDに一致する情報を表示します

optional arguments:
  -h, --help            show this help message and exit
  -o OUTPUT, --output OUTPUT
                        アウトプットファイルを指定します
  --json                json形式で出力します
  -v, --vervose         詳細表示
```
