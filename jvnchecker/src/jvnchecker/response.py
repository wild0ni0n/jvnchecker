from datetime import datetime
from enum import Enum
from typing import List

class Severity(Enum):
    CRITICAL =  'Critical'
    High = 'High'
    Medium = 'Medium'
    Low = 'Low'

class Status:
    version: str
    method: str
    lang: str
    ret_cd: int
    ret_max: int
    err_cd: str
    err_msg: str
    total_res: int
    total_res_ret: int
    first_res: int
    feed: str
    start_item: int
    max_count_item: int
    cpe_name: str
    vendor_id: int
    product_id: int
    keyword: str
    vector: str
    range_date_public: str
    range_date_published: str
    range_date_first_
    published: str
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


class Product:
    pname: str
    cpe: str
    pid: int


class Vendor:
    vname: str
    cpe: str
    vid: int
    products: List[Product]

class Reference:
    source: str
    id: str
    text: str

class Cvss:
    score: float
    severity: Severity
    vector: str
    version: str
    type: str

class Overview:
    title: str
    link: str
    description: str
    creator: str
    jvn_id: str
    references: List[Reference]
    vendor: Vendor
    cvss: List[Cvss]
    date: datetime
    issued_date: datetime
    modified_date: datetime

