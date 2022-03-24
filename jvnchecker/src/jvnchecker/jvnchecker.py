import argparse



def argparse_setup():
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers()

    parser_alert = subparsers.add_parser('alert', help='注意警戒情報一覧を検索します')
    parser_alert.add_argument('--cpe', help="CPEを入力します")
    parser_alert.set_defaults(handler=command_alert)

    parser_vendor = subparsers.add_parser('vendor', help="ベンダー名一覧を検索します")
    parser_vendor.add_argument('--name', help="ベンダー名を入力します")
    parser_vendor.add_argument('--cpe', help="CPEを入力します")
    parser_vendor.set_defaults(handler=command_vendor)

    parser_product = subparsers.add_parser('product', help='製品名一覧を検索します。CPE、ベンダーID、プロダクトIDはいれずか1つのみ指定してください')
    parser_product.add_argument('-k', '--keyword', help="キーワード検索を行います。ワイルドカード \"*\" 指定不可 (\"*\"を指定した場合、\"*\"を含む項目をフィルタリング) 大文字／小文字区別なし", type=str, default="")
    parser_product.add_argument('--cpe', help="CPEを入力します")
    parser_product.add_argument('--vid', help="ベンダーIDを入力します")
    parser_product.add_argument('--pid', help="プロダクトIDを入力します")
    parser_product.set_defaults(handler=command_product)

    parser_overview = subparsers.add_parser('overview', help="脆弱性概要一覧を検索します。CPE、ベンダーID、プロダクトIDはいれずか1つのみ指定してください")
    parser_overview.add_argument('-k', '--keyword', help="キーワード検索を行います。ワイルドカード \"*\" 指定不可 (\"*\"を指定した場合、\"*\"を含む項目をフィルタリング) 大文字／小文字区別なし", type=str, default="")
    parser_overview.add_argument('--cpe', help="CPEを入力します")
    parser_overview.add_argument('--vid', help="ベンダーIDを入力します")
    parser_overview.add_argument('--pid', help="プロダクトIDを入力します")
    parser_overview.set_defaults(handler=command_overview)

    parser_detail = subparsers.add_parser('detail', help="脆弱性詳細を検索します")
    parser_detail.add_argument('JVNDB_ID', help="JVNDBのIDを指定します")
    parser_detail.set_defaults(handler=command_detail)

    parser_stat = subparsers.add_parser('stat', help='統計情報を検索します')
    parser_stat.set_defaults(handler=command_stat)

    parser.add_argument('-o', '--output', help="アウトプットファイルを指定します", type=argparse.FileType("wa", encoding="utf8"), default=None)
    parser.add_argument('--json', help="json形式で出力します", action='store_true')
    parser.add_argument('-v', '--vervose', help="コマンド結果を詳細に表示するようにします", action='store_true')
    return parser


def command_alert(args):
    pass

def command_vendor(args):
    pass

def command_product(args):
    pass

def command_overview(args):
    pass

def command_detail(args):
    pass

def command_stat(args):
    pass

def main():
    parser = argparse_setup()
    args = parser.parse_args()

    if hasattr(args, 'handler'):
        args.handler(args)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
