
import argparse
from lxml import html
import requests
from pprint import pprint
from typing import List
from dataclasses import dataclass
from operator import attrgetter

JVN_URL = "https://jvndb.jvn.jp/myjvn"
overview_list_params = {
    'method': 'getVulnOverviewList',
    'feed': 'hnd',
    'startItem': 1,
    'maxCountItem': 50,
    'cpeName': '',
    'vendorId': '',
    'productId': '',
    'keyword': '',
    'severity': '',
    'vector': '',
    'rangeDatePublic': 'n',
    'rangeDatePublished': 'n',
    'rangeDateFirstPublished': 'n',
    'datePublicStartY': '',
    'datePublicStartM': '',
    'datePublicStartD': '',
    'datePublicEndY': '',
    'datePublicEndM': '',
    'datePublicEndD': '',
    'datePublishedStartY': '',
    'datePublishedStartM': '',
    'datePublishedStartD': '',
    'datePublishedEndY': '',
    'datePublishedEndM': '',
    'datePublishedEndD': '',
    'dateFirstPublishedStartY': '',
    'dateFirstPublishedStartM': '',
    'dateFirstPublishedStartD': '',
    'dateFirstPublishedEndY': '',
    'dateFirstPublishedEndM': '',
    'dateFirstPublishedEndD': '',
    'lang': 'ja'

}

vuln_detail_info_params = {
    'method': 'getVulnDetailInfo',
    'feed': 'hnd',
    'startItem': 1,
    'maxCountItem': 10,
    'vulnId': '',
    'lang': 'ja'
}

vendor_list_params = {
    'method': 'getVendorList',
    'feed': 'hnd',
    'startItem': 1,
    'maxCountItem': 10000,
    'cpeName': '',
    'keyword': '',
    'lang': 'ja'
}

@dataclass
class OutputItem():
    name: str
    value: str
    order: int = 0

def get_xml_tree(url, params, vervose=False):
    result = requests.get(url, params=params)
    print(result.url) if vervose else ''
    tree = html.fromstring(result.content)
    return tree

def output(data_list: List, is_output_json: bool = False, file_handler: argparse.FileType = None):
    if is_output_json:
        if file_handler is not None:
            output_file(data_list, file_handler, True)
        else:
            json_list = to_json(data_list)
            output_stdout(json_list, True)
    else:
        if file_handler is not None:
            output_file(data_list, file_handler, False)
        else:
            output_stdout(data_list, False)

def output_stdout(data_list: List, is_json: bool):
    if is_json:
        pprint(data_list)
    else:
        for items in data_list:  
            if not hasattr(items, 'order'):
                items.sort(key=attrgetter('order'))
                output_stdout(items, False)
            else:
                message = '{}: {}'.format(items.name, items.value)
                print(message)

def output_file(data_list: List, output_file: argparse.FileType, is_json: bool):
    if is_json:
        json_list = to_json(data_list)
        output_file.write(json_list)

def to_json(items):
    if isinstance(items, List):
        converted = []
        if isinstance(items[0], OutputItem):
            converted_json = {}
            for item in items:
                converted_json[item.name] = item.value
            return converted_json
        elif isinstance(items[0], List):
            for item in items:
                converted.append(to_json(item))
    return converted

def argparse_setup():
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers()

    parser_vendor = subparsers.add_parser('vendor', help="?????????????????????????????????ID??????????????????")
    parser_vendor.add_argument('--name', help="?????????????????????????????????")
    parser_vendor.add_argument('--cpe', help="????????????CPE??????????????????")
    parser_vendor.set_defaults(handler=command_vendor)

    parser_list = subparsers.add_parser('list', help="?????????????????????????????????????????????????????????????????????????????????")
    parser_list.add_argument('-k', '--keyword', help="???????????????????????????????????????????????????????????? \"*\" ???????????? (\"*\"????????????????????????\"*\"???????????????????????????????????????) ?????????????????????????????????", type=str, default="")
    parser_list.add_argument('-i', '--id', help="????????????ID???????????????????????????", type=int)
    parser_list.set_defaults(handler=command_list)

    parser_detail = subparsers.add_parser('detail', help="JVNDB???ID???????????????????????????????????????")
    parser_detail.add_argument('JVNDB_ID', help="JVNDB???ID??????????????????")
    parser_detail.set_defaults(handler=command_detail)

    parser.add_argument('-o', '--output', help="????????????????????????????????????????????????", type=argparse.FileType("wa", encoding="utf8"), default=None)
    parser.add_argument('--json', help="json????????????????????????", action='store_true')
    parser.add_argument('-v', '--vervose', help="????????????", action='store_true')
    return parser

def find_relateditem(relateditems):
    items = []
    if isinstance(relateditems, list):
        for item in relateditems:
            if item.find('name').text == 'Common Vulnerabilities and Exposures (CVE)':
                if len(items) == 0:
                    items.append(['CVE', item.find('vulinfoid').text])
                else: 
                    items.append(['CVE({})'.format(len(items)+1), item.find('vulinfoid').text])

            if item.find('name').text == 'National Vulnerability Database (NVD)':
                if len(items) == 0:
                    items.append(['NVD', item.find('vulinfoid').text])
                else: 
                    items.append(['NVD({})'.format(len(items)+1), item.find('vulinfoid').text])
    return items

def create_jvnurl(jvnid):
    return "https://jvndb.jvn.jp/ja/contents/{}/{}.html".format(jvnid[6:10], jvnid)

def command_vendor(args):
    if not args.name and not args.cpe:
        print("???????????????????????????????????????????????????CPE???????????????????????????")
        exit()
    vendor_name = args.name
    vendor_cpe = args.cpe
    vendor_list_params['keyword'] = vendor_name
    vendor_list_params['cpeName'] = vendor_cpe
    tree = get_xml_tree(JVN_URL, vendor_list_params, args.vervose)
    vendor_items = tree.xpath('//vendorinfo/vendor')
   
    items = []
    for vendor_item in vendor_items:
        items.append([
            OutputItem('Name', vendor_item.attrib['vname'], 0),
            OutputItem('vendorId', vendor_item.attrib['vid'], 1)
        ])

    output(items, args.json, args.output)

def command_list(args):
    if not args.id and not args.keyword:
        print("??????????????????????????????????????????????????????????????????ID???????????????????????????")
        exit()
    overview_list_params['vendorId'] = args.id
    overview_list_params['keyword'] = args.keyword

    def get_list(start_item=1):
        overview_list_params['startItem'] = start_item
        tree = get_xml_tree(JVN_URL, overview_list_params, args.vervose)
        count_item = len(tree.xpath('//rdf/item', namespaces={'rdf': 'http://www.w3.org/1999/02/22-rdf-syntax-ns#'}))
        
        identifiers = tree.xpath('//item/identifier/text()')
        
        items = []
        for identifier in identifiers:
            vuln_detail_info_params['vulnId'] = identifier
            tree = get_xml_tree(JVN_URL, vuln_detail_info_params)
            affected_items = tree.xpath('//vulinfo/vulinfodata/affected/affecteditem')

            affected = [OutputItem('JVNDB_ID', identifier, 0)]
            print(f'JVNDB_ID: {identifier}')
            for affected_item in affected_items:
                print(f'    Name: {"".join(affected_item.xpath("name/text()"))}')
                print(f'    Version: {"".join(affected_item.xpath("versionnumber/text()"))}')
                #affected.append([
                #    OutputItem('Name', affected_item.xpath('name/text()'), 1),
                #    OutputItem('Version', affected_item.xpath('versionnumber/text()'), 2)
                #])
            items.append(affected_item)
        
        #print(items)
        #output(items, args.json, args.output)
        if count_item == 50 and start_item < 10:
            get_list(start_item+50)

    get_list(1)

def command_detail(args):
    vuln_detail_info_params['vulnId'] = args.JVNDB_ID
    tree = get_xml_tree(JVN_URL, vuln_detail_info_params, args.vervose)
    affected_items = tree.xpath('//vulinfo/vulinfodata')

    items = []
    for item in affected_items:
        temp_array = [
            OutputItem('JVNDB_ID', args.JVNDB_ID, 0),
            OutputItem('Title', item.find('title').text, 1),
            OutputItem('URL', create_jvnurl(args.JVNDB_ID), 4),
            OutputItem('Overview', item.find('vulinfodescription/overview').text, 5),
            OutputItem('Description', item.find('solution/solutionitem/description').text, 6),
            #OutputItem(find_relateditem(item.xpath('related/relateditem[@type="advisory"]'))[0], find_relateditem(item.xpath('related/relateditem[@type="advisory"]'))[1], 7),
        ]

        if '3.0' in item.xpath('impact/cvss/@version'):
            temp_array.append(OutputItem('CVSSv3', item.find('impact/cvss[@version="3.0"]/base').tail.splitlines()[0], 2)),
        if '2.0' in item.xpath('impact/cvss/@version'):    
            temp_array.append(OutputItem('CVSSv2', item.find('impact/cvss[@version="2.0"]/base').tail.splitlines()[0], 3)),
        
        relateditems = find_relateditem(item.xpath('related/relateditem[@type="advisory"]'))
        for i, relateditem in enumerate(relateditems):
            temp_array.append(OutputItem(relateditem[0], relateditem[1], 7+i))
        items.append(temp_array)

    output(items, args.json, args.output)

def main():
    parser = argparse_setup()
    args = parser.parse_args()

    if hasattr(args, 'handler'):
        args.handler(args)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()


    
        