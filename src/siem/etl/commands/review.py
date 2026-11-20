"""Event-source review and PDF candidate commands."""
from __future__ import annotations
import argparse
from pathlib import Path
import json

from ..coverage import match_inventory
from ..vendors.rusiem import parse_html, URL
from ..pdf_docs import find_candidates
from ..console import configure_console
from ..fetcher import PublicFetcher


def download_vendor_page(fetcher=None) -> str:
    """Use the same TLS/robots/redirect boundary as every network command."""
    content,charset,_ = (fetcher or PublicFetcher()).fetch(URL)
    try:return content.decode(charset or 'utf-8')
    except (UnicodeError,LookupError):
        from bs4 import UnicodeDammit
        decoded=UnicodeDammit(content,is_html=True).unicode_markup
        if decoded is None:raise UnicodeError('Не удалось определить кодировку HTML')
        return decoded


def main(argv=None):
    configure_console()
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
