from dataclasses import dataclass
from enum import Enum


class APIFormat(Enum):
    XML  = 'xml'
    JSON = 'json'

class APILanguage(Enum):
    JA = 'ja'
    EN = 'en'

class Theme(Enum):
    SUM_ALL    = 'sumAll'
    SUM_JVN_DB = 'sumJvnDb'
    SUM_CVSS   = 'sumCvss'
    SUM_CWE    = 'sumCwe'


@dataclass
class AlertListParameters:
    '''
    注意警戒情報一覧(getAlertList)リクエストのパラメータを構築するデータクラス
    '''
    method: str                 = 'getAlertList'
    feed: str                   = 'hnd'
    start_item: int             = 1
    max_count_item: int         = 50
    date_published: int         = None
    date_first_published: int   = None
    cpe_name: str               = ''
    ft: APIFormat               = APIFormat.JSON

@dataclass
class VendorListParameters:
    '''
    ベンダ名一覧(getVendorList)リクエストのパラメータを構築するデータクラス
    '''
    method: str                 = 'getVendorList'
    feed: str                   = 'hnd'
    start_item: int             = 1
    max_count_item: int         = 10000
    cpe_name: str               = ''
    keyword: str                = ''
    lang: str                   = APILanguage.JA


@dataclass
class ProductListparameters:
    '''
    製品名一覧(getProductList)リクエストのパラメータを構築するデータクラス
    '''
    
    method: str                 = 'getProductList'
    feed: str                   = 'hnd'
    start_item: int             = 1
    max_count_item: int         = 10000
    cpe_name: str               = ''
    vendor_id: str              = ''
    product_id: str             = ''
    keyword: str                = ''
    lang: str                   = APILanguage.JA


@dataclass
class VulnOverviewListParameters:
    '''
    脆弱性対策の概要情報一覧(getVulnOverviewList)リクエストのパラメータを構築するデータクラス
    '''
    method: str                         = 'getVulnOverviewList'
    feed: str                           = 'hnd'
    start_item: int                     = 1
    max_count_item: int                 = 50
    cpe_name: str                       = ''
    vendor_id: str                      = ''
    product_id: str                     = ''
    keyword: str                        = ''
    severity: str                       = ''
    vector: str                         = ''
    range_date_public: str              = 'n'
    range_date_published: str           = 'n'
    range_date_first_published: str     = 'n'
    date_public_start_y: int            = None
    date_public_start_m: int            = None
    date_public_start_d: int            = None
    date_public_end_y: int              = None
    date_public_end_m: int              = None
    date_public_end_d: int              = None
    date_published_start_y: int         = None
    date_published_start_m: int         = None
    date_published_start_d: int         = None
    date_published_end_y: int           = None
    date_published_end_m: int           = None
    date_published_end_d: int           = None
    date_first_published_start_y: int   = None
    date_first_published_start_m: int   = None
    date_first_published_start_d: int   = None
    date_first_published_end_y: int     = None
    date_first_published_end_m: int     = None
    date_first_published_end_d: int     = None
    lang: str                           = APILanguage.JA


@dataclass
class VulnDetailInfoParameters:
    '''
    脆弱性対策の詳細情報(getVulnDetailInfo)リクエストのパラメータを構築するデータクラス
    '''
    method: str                 = 'getVulnDetailInfo'
    feed: str                   = 'hnd'
    start_item: int             = 1
    max_count_item: int         = 10
    vuln_id: str                = ''
    lang: str                   = APILanguage.JA


@dataclass
class StatisticsParameters:
    '''
    登録件数(脆弱性統計情報)、深刻度(CVSSv3統計情報)、脆弱性種別(CWE統計情報)で集計したデータ
    (getStatistics)リクエストのパラメータを構築するデータクラス
    '''
    method: str                 = 'getStatistics'
    feed: str                   = 'hnd'
    theme: Theme                = Theme.SUM_ALL
    type: str                   = 'y'
    cwe_id: str                 = ''
    pid: str                    = ''
    cpe_name: str               = ''
    date_public_start_y: int    = None
    date_public_start_m: int    = None
    date_public_end_y: int      = None
    date_public_end_m: int      = None
