import json
from pathlib import Path
import tempfile,unittest
from unittest.mock import patch
from siem.etl.commands import collection

class CliExitStatusTests(unittest.TestCase):
 def registry(self,path):
  path.write_text(json.dumps({'vendors':[{'id':'p','name':'P','sources':[{'id':'s','url':'https://example.test','mode':'generic'}]}]}),'utf-8')
 def test_crawl_distinguishes_complete_unavailable_and_no_data(self):
  with tempfile.TemporaryDirectory() as d:
   root=Path(d);registry=root/'registry.json';self.registry(registry)
   outputs=[
    ({'vendors':[{'source_results':[{'status':'ok'}]}],'facts':[{}],'errors':[],'totals':{'facts':1,'errors':0}},0),
    ({'vendors':[{'source_results':[{'status':'access_disallowed'}]}],'facts':[{}],'errors':[{}],'totals':{'facts':1,'errors':1}},3),
    ({'vendors':[{'source_results':[{'status':'empty_review_required'}]}],'facts':[],'errors':[],'totals':{'facts':0,'errors':0}},4)]
   for index,(result,expected) in enumerate(outputs):
    with self.subTest(expected=expected),patch.object(collection,'collect',return_value=result):
     code=collection.main(['crawl','--registry',str(registry),'--output',str(root/f'{index}.json'),
                           '--fixture-dir',str(root)])
     self.assertEqual(expected,code)
if __name__=='__main__':unittest.main()
