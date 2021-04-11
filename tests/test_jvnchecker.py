import unittest
from test.support import captured_stdout
from unittest.mock import Mock, patch
from jvnchecker import jvnchecker
from lxml import html

def load_mockdata(filename):
    with open('tests/test_xml/'+ filename, encoding='utf-8') as f:
        xmldata = f.read()
    return xmldata.encode()

def side_effect_command_list_func(*args):
    if args[1]['method'] == 'getVulnOverviewList':
        return html.fromstring(load_mockdata('VulnOverviewList.xml'))
    else:
        if args[1]['vulnId'] == 'JVNDB-1111-111111':
            return html.fromstring(load_mockdata('VulnDetailInfo.xml'))
        elif args[1]['vulnId'] == 'JVNDB-2222-222222':
            return html.fromstring(load_mockdata('VulnDetailInfo2.xml'))


class TestJvnChecker(unittest.TestCase):
    
    @patch('jvnchecker.jvnchecker.requests')
    def test_get_xml_tree(self, mock_requests):
        url = "https://localhost"
        params = ["param1"]
        mock_response = Mock(content=load_mockdata('Vendorlist.xml'))
        mock_requests.get.return_value = mock_response
        tree = jvnchecker.get_xml_tree(url, params, False)
        self.assertEqual(tree.xpath('//vendorinfo/vendor[1]/@vname')[0], "vendortest")


    @patch('jvnchecker.jvnchecker.output_stdout')
    @patch('jvnchecker.jvnchecker.output_file')
    @patch('jvnchecker.jvnchecker.to_json', return_value=[1])
    def test_output(self, mock_to_json, mock_output_file, mock_output_stdout):
        jvnchecker.output([1], True, 1)
        mock_output_file.assert_called_with([1], 1, 1)

        jvnchecker.output([1], True, None)
        mock_output_stdout.assert_called_with([1], True)

        jvnchecker.output([1], False, 1)
        mock_output_file.assert_called_with([1], 1, False)

        jvnchecker.output([1], False, None)
        mock_output_stdout.assert_called_with([1], False)

        
    def test_output_stdout(self):
        with captured_stdout() as stdout:
            jvnchecker.output_stdout(data_list=[jvnchecker.OutputItem('foo1', 'bar1', 1)], is_json=False)
            lines = stdout.getvalue().splitlines()

        self.assertEqual(lines[0], 'foo1: bar1')

    def test_to_json(self):
        test_items = [[
            jvnchecker.OutputItem('foo1', 'bar1', 1),
            jvnchecker.OutputItem('foo2', 'bar2', 2)
        ], [
            jvnchecker.OutputItem('foo3', 'bar3', 3),
            jvnchecker.OutputItem('foo4', 'bar4', 4)
        ]]
        result = jvnchecker.to_json(items=test_items)
        
        correct_list = [{
            'foo1': 'bar1',
            'foo2': 'bar2'
        },{
            'foo3': 'bar3',
            'foo4': 'bar4'
        }]
        self.assertEqual(result, correct_list)
    
    def test_argparse_setup(self):
        parser = jvnchecker.argparse_setup()
        test_parser1 = parser.parse_args(['vendor', 'foo'])
        test_parser2 = parser.parse_args(['list', '-k', 'bar'])
        test_parser3 = parser.parse_args(['detail', 'baz'])

        self.assertEqual(test_parser1.VendorName, 'foo')
        self.assertEqual(test_parser2.keyword, 'bar')
        self.assertEqual(test_parser3.JVNDB_ID, 'baz')
    
    def test_find_relateditem(self):
        root = html.fromstring(load_mockdata('VulnDetailInfo.xml'))
        relateditems = root.xpath('//vulinfo/vulinfodata/related/relateditem[@type="advisory"]')
        items = jvnchecker.find_relateditem(relateditems)

        self.assertEqual(items[0], ['CVE', 'CVE-3333-333333'])
        self.assertEqual(items[1], ['CVE(2)', 'CVE-4444-444444'])
        self.assertEqual(items[2], ['CVE(3)', 'CVE-5555-555555'])

    def test_create_jvnurl(self):
        url = jvnchecker.create_jvnurl('JVNDB-1111-111111')
        self.assertEqual(url, 'https://jvndb.jvn.jp/ja/contents/1111/JVNDB-1111-111111.html')

    @patch('jvnchecker.jvnchecker.get_xml_tree', return_value=html.fromstring(load_mockdata('Vendorlist.xml')))
    def test_command_vendor(self, mock_get_xml_tree):
        mock_get_xml_tree.return_value 
        parser = jvnchecker.argparse_setup()
        test_arg = parser.parse_args(['vendor', 'foo'])

        with captured_stdout() as stdout:
            jvnchecker.command_vendor(test_arg)
            lines = stdout.getvalue().splitlines()

        self.assertEqual(lines[0], 'Name: vendortest')
        self.assertEqual(lines[1], 'vendorId: 12345')

    @patch('jvnchecker.jvnchecker.get_xml_tree', return_value=html.fromstring(load_mockdata('Vendorlist.xml')))
    def test_command_vendor_json(self, mock_get_xml_tree):
        parser = jvnchecker.argparse_setup()
        test_arg = parser.parse_args(['--json', 'vendor', 'foo'])

        with captured_stdout() as stdout:
            jvnchecker.command_vendor(test_arg)
            lines = stdout.getvalue().splitlines()

        self.assertEqual(lines[0], '[{\'Name\': \'vendortest\', \'vendorId\': \'12345\'},')
        self.assertEqual(lines[1], ' {\'Name\': \'vendortest2\', \'vendorId\': \'12346\'},')

    @patch('jvnchecker.jvnchecker.get_xml_tree')
    def test_command_list(self, mock_get_xml_tree):
        mock_get_xml_tree.side_effect = side_effect_command_list_func
        
        parser = jvnchecker.argparse_setup()
        test_arg = parser.parse_args(['list', '-k', 'foo'])
            
        with captured_stdout() as stdout:
            jvnchecker.command_list(test_arg)
            lines = stdout.getvalue().splitlines()

        self.assertEqual(lines[0], 'JVNDB_ID: JVNDB-1111-111111')
        self.assertEqual(lines[1], 'Name: ネームテスト')
        self.assertEqual(lines[2], 'Version: 1.0.0')
        self.assertEqual(lines[3], 'JVNDB_ID: JVNDB-2222-222222')
        self.assertEqual(lines[4], 'Name: ネームテスト2')
        self.assertEqual(lines[5], 'Version: 2.0.0')

    @patch('jvnchecker.jvnchecker.get_xml_tree')
    def test_command_list_json(self, mock_get_xml_tree):
        mock_get_xml_tree.side_effect = side_effect_command_list_func
        
        parser = jvnchecker.argparse_setup()
        test_arg = parser.parse_args(['--json', 'list', '-k', 'foo'])

        with captured_stdout() as stdout:
            jvnchecker.command_list(test_arg)
            lines = stdout.getvalue().splitlines()

        self.assertEqual(lines[0], "[{'JVNDB_ID': 'JVNDB-1111-111111', 'Name': 'ネームテスト', 'Version': '1.0.0'},")
        self.assertEqual(lines[1], " {'JVNDB_ID': 'JVNDB-2222-222222', 'Name': 'ネームテスト2', 'Version': '2.0.0'}]")
       
    @patch('jvnchecker.jvnchecker.get_xml_tree', return_value=html.fromstring(load_mockdata('VulnDetailInfo.xml')))
    def test_command_detail(self, mock_get_xml_tree):
        parser = jvnchecker.argparse_setup()
        test_arg = parser.parse_args(['detail', 'JVNDB-1111-111111'])

        with captured_stdout() as stdout:
            jvnchecker.command_detail(test_arg)
            lines = stdout.getvalue().splitlines()
        
        self.assertEqual(lines[0], 'JVNDB_ID: JVNDB-1111-111111')
        self.assertEqual(lines[1], 'Title: タイトルテスト')
        self.assertEqual(lines[2], 'CVSSv3: 7.2')
        self.assertEqual(lines[3], 'CVSSv2: 6.5')
        self.assertEqual(lines[4], 'URL: https://jvndb.jvn.jp/ja/contents/1111/JVNDB-1111-111111.html')
        self.assertEqual(lines[5], 'Overview: 概要概要概要')
        self.assertEqual(lines[6], 'Description: 対策説明対策説明対策説明 ')

    @patch('jvnchecker.jvnchecker.get_xml_tree', return_value=html.fromstring(load_mockdata('VulnDetailInfo.xml')))
    def test_command_detail_json(self, mock_get_xml_tree):
        parser = jvnchecker.argparse_setup()
        test_arg = parser.parse_args(['--json', 'detail', 'JVNDB-1111-111111'])

        with captured_stdout() as stdout:
            jvnchecker.command_detail(test_arg)
            lines = stdout.getvalue().splitlines()
        
        self.assertEqual(lines[0], "[{'CVE': 'CVE-3333-333333',")
        self.assertEqual(lines[1], "  'CVE(2)': 'CVE-4444-444444',")
        self.assertEqual(lines[2], "  'CVE(3)': 'CVE-5555-555555',")
        self.assertEqual(lines[3], "  'CVSSv2': '6.5',")
        self.assertEqual(lines[4], "  'CVSSv3': '7.2',")
        self.assertEqual(lines[5], "  'Description': '対策説明対策説明対策説明 ',")
        self.assertEqual(lines[6], "  'JVNDB_ID': 'JVNDB-1111-111111',")
        self.assertEqual(lines[7], "  'Overview': '概要概要概要',")
        self.assertEqual(lines[8], "  'Title': 'タイトルテスト',")
        self.assertEqual(lines[9], "  'URL': 'https://jvndb.jvn.jp/ja/contents/1111/JVNDB-1111-111111.html'}]")