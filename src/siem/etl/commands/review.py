"""Event-source review and PDF candidate commands."""
from __future__ import annotations
import argparse
from pathlib import Path
from urllib.parse import urlparse
from urllib.request import Request, urlopen
from urllib.robotparser import RobotFileParser
import json

from ..coverage import match_inventory
from ..vendors.rusiem import parse_html, URL
from ..pdf_docs import find_candidates

AGENT = 'SIEMResearchETL/0.3 (non-commercial academic prototype)'


def download_vendor_page() -> str:
    """One allowlisted source, obey published robots instructions. No crawling."""
    u = urlparse(URL)
    robots_url = f'{u.scheme}://{u.netloc}/robots.txt'
    robots = RobotFileParser()
    try:
        with urlopen(Request(robots_url, headers={'User-Agent': AGENT}), timeout=12) as response:
            robot_text = response.read(500_000).decode('utf-8',errors='replace')
        robots.parse(robot_text.splitlines())
    except Exception as exc:
        raise RuntimeError('Не удалось проверить robots.txt; онлайн-загрузка отменена') from exc
    if not robots.can_fetch(AGENT, URL):
        raise RuntimeError('robots.txt не разрешает получение страницы этим клиентом')
    with urlopen(Request(URL,headers={'User-Agent': AGENT,'Accept':'text/html'}),timeout=20) as response:
        content = response.read(3_000_001)
        if len(content) > 3_000_000:
            raise ValueError('Размер исходной страницы превышает лимит 3 МБ')
        charset = response.headers.get_content_charset() or 'utf-8'
        return content.decode(charset,errors='replace')


def main(argv=None):
    parser = argparse.ArgumentParser(description='ETL evidence / RuSIEM sources / PT PDF review')
    sub = parser.add_subparsers(dest='command',required=True)
    extract = sub.add_parser('rusiem',help='Extract vendor source list')
    extract.add_argument('--html',type=Path,help='Offline HTML (omit for live fetch)')
    extract.add_argument('--output',type=Path,required=True)
    match = sub.add_parser('match',help='Check required sources against extracted evidence')
    match.add_argument('--catalog',type=Path,required=True)
    match.add_argument('--inventory',type=Path,required=True)
    match.add_argument('--output',type=Path)
    pdf = sub.add_parser('pdf-candidates',help='Extract keywords for human review')
    pdf.add_argument('--pdf',type=Path,required=True)
    pdf.add_argument('--url',required=True)
    pdf.add_argument('--version',required=True)
    pdf.add_argument('--keyword',action='append',required=True)
    pdf.add_argument('--output',type=Path,required=True)
    args = parser.parse_args(argv)
    if args.command=='rusiem':
        html = args.html.read_text(encoding='utf-8') if args.html else download_vendor_page()
        result=parse_html(html)
    elif args.command=='match':
        facts=json.loads(args.catalog.read_text(encoding='utf-8'))
        inv=json.loads(args.inventory.read_text(encoding='utf-8'))
        result={'siem_id':facts['siem_id'],
                'coverage':match_inventory(inv['required_sources'],facts['records'])}
    else:
        result=find_candidates(args.pdf,args.keyword,args.url,args.version)
    value=json.dumps(result,ensure_ascii=False,indent=2)+'\n'
    if args.output:
        args.output.parent.mkdir(parents=True,exist_ok=True)
        args.output.write_text(value,encoding='utf-8')
    print(value)

if __name__=='__main__':main()
